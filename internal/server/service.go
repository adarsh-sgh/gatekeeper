// Package server implements the Gatekeeper gRPC service and its HTTP mirror.
package server

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/audit"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/metrics"
	"github.com/adarsh-sgh/gatekeeper/internal/policy"
	"github.com/adarsh-sgh/gatekeeper/internal/store"
)

type Service struct {
	pb.UnimplementedGatekeeperServer
	store store.Store
	cache *policy.Cache
	log   *slog.Logger
}

func New(st store.Store, log *slog.Logger) *Service {
	return &Service{store: st, cache: policy.NewCache(), log: log}
}

// Check is fail-closed end to end: an evaluation or audit-write error returns
// an error rather than a decision, so a caller can never act on an unlogged allow.
func (s *Service) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	claims, err := requireScope(ctx, auth.ScopeCheck)
	if err != nil {
		return nil, err
	}
	if req.GetSubject().GetId() == "" || req.GetAction() == "" || req.GetResource().GetType() == "" {
		return nil, status.Error(codes.InvalidArgument, "subject.id, action and resource.type are required")
	}
	ev, err := s.decide(ctx, claims, policy.Input{Tenant: claims.Tenant, Action: req.Action,
		Subject:  audit.Subject{ID: req.Subject.Id, Roles: req.Subject.Roles, Attrs: req.Subject.GetAttrs().AsMap()},
		Resource: audit.Resource{Type: req.Resource.Type, ID: req.Resource.Id, Attrs: req.Resource.GetAttrs().AsMap()}})
	if err != nil {
		return nil, err
	}
	return &pb.CheckResponse{Allowed: ev.Allowed, Reason: ev.Reason, PolicyVersion: ev.PolicyVersion, AuditSeq: ev.Seq}, nil
}

// decide evaluates in for claims.Tenant and appends the decision to the audit
// chain; Check and the Envoy ext_authz adapter share it.
func (s *Service) decide(ctx context.Context, claims *auth.Claims, in policy.Input) (audit.Event, error) {
	tenant := claims.Tenant
	st, err := s.store.GetTenantState(ctx, tenant)
	if err != nil {
		return audit.Event{}, internal("get tenant state", err)
	}
	ev := audit.Event{TS: time.Now().UTC(), Tenant: tenant, Caller: claims.Subject, Subject: in.Subject,
		Action: in.Action, Resource: in.Resource, PolicyVersion: st.Active, Reason: "no active policy"}
	if st.Disabled {
		ev.Reason, st.Active, st.Shadow = "tenant disabled", 0, 0
	}
	if st.Active != 0 {
		d, err := s.eval(ctx, tenant, st.Active, in)
		if err != nil {
			return audit.Event{}, internal("evaluate policy", err)
		}
		ev.Allowed, ev.Reason = d.Allowed, d.Reason
	}
	if st.Shadow != 0 {
		// Shadow errors are logged, never surfaced: a broken candidate must not break traffic.
		if sd, err := s.eval(ctx, tenant, st.Shadow, in); err != nil {
			s.log.Warn("shadow eval failed", "tenant", tenant, "version", st.Shadow, "err", err)
			metrics.Errors.WithLabelValues("shadow_eval").Inc()
		} else {
			ev.ShadowVersion, ev.ShadowAllowed, ev.ShadowDiverge = st.Shadow, sd.Allowed, sd.Allowed != ev.Allowed
			if ev.ShadowDiverge {
				metrics.ShadowDivergence.WithLabelValues(tenant).Inc()
			}
		}
	}
	if err := s.store.AppendAudit(ctx, &ev); err != nil {
		return audit.Event{}, internal("append audit", err)
	}
	metrics.Checks.WithLabelValues(tenant, decisionLabel(ev.Allowed)).Inc()
	return ev, nil
}

func (s *Service) eval(ctx context.Context, tenant string, version int64, in policy.Input) (policy.Decision, error) {
	c, err := s.cache.Get(ctx, tenant, version, func() (string, error) {
		p, err := s.store.GetPolicy(ctx, tenant, version)
		return p.Rego, err
	})
	if err != nil {
		return policy.Decision{}, err
	}
	start := time.Now()
	defer func() { metrics.EvalDuration.Observe(time.Since(start).Seconds()) }()
	return c.Eval(ctx, in)
}

func (s *Service) PutPolicy(ctx context.Context, req *pb.PutPolicyRequest) (*pb.PutPolicyResponse, error) {
	claims, tenant, err := forTenant(ctx, auth.ScopePolicyWrite, req.Tenant)
	if err != nil {
		return nil, err
	}
	if _, err := policy.Compile(ctx, req.Rego); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	key := req.IdempotencyKey
	if md, _ := metadata.FromIncomingContext(ctx); key == "" && len(md.Get("idempotency-key")) > 0 {
		key = md.Get("idempotency-key")[0] // HTTP Idempotency-Key header via the gateway
	}
	p, created, err := s.store.PutPolicy(ctx, tenant, req.Rego, key)
	if errors.Is(err, store.ErrIdempotencyMismatch) {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	if err != nil {
		return nil, internal("put policy", err)
	}
	st, err := s.store.GetTenantState(ctx, tenant)
	if err != nil {
		return nil, internal("get tenant state", err)
	}
	if created {
		if req.Shadow {
			st.Shadow = p.Version
		} else {
			st.Active = p.Version // slots are independent: a shadow keeps running
		}
		if err := s.store.SetTenantState(ctx, tenant, st); err != nil {
			return nil, internal("set tenant state", err)
		}
		s.log.Info("policy stored", "tenant", tenant, "version", p.Version, "shadow", req.Shadow, "by", claims.Subject)
	}
	return &pb.PutPolicyResponse{Version: p.Version, Created: created, Shadow: st.Shadow == p.Version}, nil
}

func (s *Service) GetPolicy(ctx context.Context, req *pb.GetPolicyRequest) (*pb.Policy, error) {
	_, tenant, err := forTenant(ctx, auth.ScopePolicyWrite, req.Tenant)
	if err != nil {
		return nil, err
	}
	p, err := s.store.GetPolicy(ctx, tenant, req.Version)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "policy version %d not found", req.Version)
	} else if err != nil {
		return nil, internal("get policy", err)
	}
	return &pb.Policy{Tenant: p.Tenant, Version: p.Version, Rego: p.Rego, CreateTime: timestamppb.New(p.CreatedAt)}, nil
}

func (s *Service) PromotePolicy(ctx context.Context, req *pb.PromotePolicyRequest) (*pb.PromotePolicyResponse, error) {
	claims, tenant, err := forTenant(ctx, auth.ScopePolicyWrite, req.Tenant)
	if err != nil {
		return nil, err
	}
	if _, err := s.store.GetPolicy(ctx, tenant, req.Version); errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "policy version %d not found", req.Version)
	} else if err != nil {
		return nil, internal("get policy", err)
	}
	st, err := s.store.GetTenantState(ctx, tenant)
	if err != nil {
		return nil, internal("get tenant state", err)
	}
	st.Active = req.Version
	if st.Shadow == req.Version {
		st.Shadow = 0
	}
	if err := s.store.SetTenantState(ctx, tenant, st); err != nil {
		return nil, internal("set tenant state", err)
	}
	s.log.Info("policy promoted", "tenant", tenant, "version", req.Version, "by", claims.Subject)
	return &pb.PromotePolicyResponse{ActiveVersion: st.Active}, nil
}

func (s *Service) UnsetPolicy(ctx context.Context, req *pb.UnsetPolicyRequest) (*pb.UnsetPolicyResponse, error) {
	claims, tenant, err := forTenant(ctx, auth.ScopePolicyWrite, req.Tenant)
	if err != nil {
		return nil, err
	}
	st, err := s.store.GetTenantState(ctx, tenant)
	if err != nil {
		return nil, internal("get tenant state", err)
	}
	if req.Shadow {
		st.Shadow = 0
	} else {
		st.Active = 0
	}
	if err := s.store.SetTenantState(ctx, tenant, st); err != nil {
		return nil, internal("set tenant state", err)
	}
	s.log.Info("policy unset", "tenant", tenant, "shadow", req.Shadow, "by", claims.Subject)
	return &pb.UnsetPolicyResponse{ActiveVersion: st.Active, ShadowVersion: st.Shadow}, nil
}

var tenantName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (s *Service) PutTenant(ctx context.Context, req *pb.PutTenantRequest) (*pb.Tenant, error) {
	claims, err := requireScope(ctx, auth.ScopeTenantAdmin)
	if err != nil {
		return nil, err
	}
	t := req.GetTenant()
	if !tenantName.MatchString(t.GetName()) {
		return nil, status.Errorf(codes.InvalidArgument, "tenant name %q must match %s", t.GetName(), tenantName)
	}
	if _, err := s.store.PutTenant(ctx, store.Tenant{Name: t.Name, DisplayName: t.DisplayName, Disabled: t.Disabled}); err != nil {
		return nil, internal("put tenant", err)
	}
	s.log.Info("tenant stored", "tenant", t.Name, "disabled", t.Disabled, "by", claims.Subject)
	return s.GetTenant(ctx, &pb.GetTenantRequest{Name: t.Name})
}

func (s *Service) GetTenant(ctx context.Context, req *pb.GetTenantRequest) (*pb.Tenant, error) {
	if _, err := requireScope(ctx, auth.ScopeTenantAdmin); err != nil {
		return nil, err
	}
	t, err := s.store.GetTenant(ctx, req.Name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "tenant %q not found", req.Name)
	} else if err != nil {
		return nil, internal("get tenant", err)
	}
	return s.tenantProto(ctx, t)
}

func (s *Service) ListTenants(ctx context.Context, _ *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	if _, err := requireScope(ctx, auth.ScopeTenantAdmin); err != nil {
		return nil, err
	}
	ts, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, internal("list tenants", err)
	}
	out := &pb.ListTenantsResponse{Tenants: make([]*pb.Tenant, 0, len(ts))}
	for _, t := range ts {
		pt, err := s.tenantProto(ctx, t)
		if err != nil {
			return nil, err
		}
		out.Tenants = append(out.Tenants, pt)
	}
	return out, nil
}

func (s *Service) DeleteTenant(ctx context.Context, req *pb.DeleteTenantRequest) (*pb.DeleteTenantResponse, error) {
	claims, err := requireScope(ctx, auth.ScopeTenantAdmin)
	if err != nil {
		return nil, err
	}
	if err := s.store.DeleteTenant(ctx, req.Name); errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "tenant %q not found", req.Name)
	} else if err != nil {
		return nil, internal("delete tenant", err)
	}
	s.log.Info("tenant deleted", "tenant", req.Name, "by", claims.Subject)
	return &pb.DeleteTenantResponse{}, nil
}

func (s *Service) tenantProto(ctx context.Context, t store.Tenant) (*pb.Tenant, error) {
	st, err := s.store.GetTenantState(ctx, t.Name)
	if err != nil {
		return nil, internal("get tenant state", err)
	}
	return &pb.Tenant{Name: t.Name, DisplayName: t.DisplayName, Disabled: t.Disabled,
		ActiveVersion: st.Active, ShadowVersion: st.Shadow, CreateTime: timestamppb.New(t.CreatedAt)}, nil
}

func (s *Service) ListAuditEvents(ctx context.Context, req *pb.ListAuditEventsRequest) (*pb.ListAuditEventsResponse, error) {
	claims, err := requireScope(ctx, auth.ScopeAuditRead)
	if err != nil {
		return nil, err
	}
	limit := int(req.Limit)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	evs, err := s.store.ListAudit(ctx, claims.Tenant, req.AfterSeq, limit)
	if err != nil {
		return nil, internal("list audit", err)
	}
	out := &pb.ListAuditEventsResponse{Events: make([]*pb.AuditEvent, 0, len(evs))}
	for _, e := range evs {
		out.Events = append(out.Events, toProto(e))
	}
	return out, nil
}

func (s *Service) VerifyAuditChain(ctx context.Context, _ *pb.VerifyAuditChainRequest) (*pb.VerifyAuditChainResponse, error) {
	claims, err := requireScope(ctx, auth.ScopeAuditRead)
	if err != nil {
		return nil, err
	}
	chk := audit.NewChecker()
	for after := int64(0); ; {
		page, err := s.store.ListAudit(ctx, claims.Tenant, after, 500)
		if err != nil {
			return nil, internal("list audit", err)
		}
		if len(page) == 0 {
			return &pb.VerifyAuditChainResponse{Ok: true, EventsChecked: chk.Checked()}, nil
		}
		for _, e := range page {
			if !chk.Next(e) {
				return &pb.VerifyAuditChainResponse{Ok: false, EventsChecked: chk.Checked(), BrokenAtSeq: e.Seq}, nil
			}
		}
		after = page[len(page)-1].Seq
	}
}

// forTenant resolves the tenant an admin RPC acts on: the caller's own by
// default, another one only with scope tenants:admin.
func forTenant(ctx context.Context, scope, requested string) (*auth.Claims, string, error) {
	c, err := requireScope(ctx, scope)
	if err != nil {
		return nil, "", err
	}
	if requested == "" || requested == c.Tenant {
		return c, c.Tenant, nil
	}
	if !c.HasScope(auth.ScopeTenantAdmin) {
		return nil, "", status.Errorf(codes.PermissionDenied, "scope %q required to act on tenant %q", auth.ScopeTenantAdmin, requested)
	}
	return c, requested, nil
}

func requireScope(ctx context.Context, scope string) (*auth.Claims, error) {
	c, ok := auth.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing bearer token")
	}
	if !c.HasScope(scope) {
		return nil, status.Errorf(codes.PermissionDenied, "scope %q required", scope)
	}
	return c, nil
}

func internal(op string, err error) error {
	metrics.Errors.WithLabelValues(op).Inc()
	return status.Errorf(codes.Internal, "%s: %v", op, err)
}

func decisionLabel(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func toProto(e audit.Event) *pb.AuditEvent {
	sa, _ := structpb.NewStruct(e.Subject.Attrs)
	ra, _ := structpb.NewStruct(e.Resource.Attrs)
	return &pb.AuditEvent{Seq: e.Seq, Ts: timestamppb.New(e.TS), Tenant: e.Tenant, Caller: e.Caller,
		Subject:       &pb.Subject{Id: e.Subject.ID, Roles: e.Subject.Roles, Attrs: sa},
		Action:        e.Action,
		Resource:      &pb.Resource{Type: e.Resource.Type, Id: e.Resource.ID, Attrs: ra},
		PolicyVersion: e.PolicyVersion, Allowed: e.Allowed, Reason: e.Reason,
		ShadowVersion: e.ShadowVersion, ShadowAllowed: e.ShadowAllowed, ShadowDiverged: e.ShadowDiverge,
		PrevHash: e.PrevHash, Hash: e.Hash}
}
