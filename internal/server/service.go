// Package server implements the Gatekeeper gRPC service and its HTTP mirror.
package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
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
	tenant := claims.Tenant
	st, err := s.store.GetTenantState(ctx, tenant)
	if err != nil {
		return nil, internal("get tenant state", err)
	}
	in := policy.Input{Tenant: tenant, Action: req.Action,
		Subject:  audit.Subject{ID: req.Subject.Id, Roles: req.Subject.Roles, Attrs: req.Subject.GetAttrs().AsMap()},
		Resource: audit.Resource{Type: req.Resource.Type, ID: req.Resource.Id, Attrs: req.Resource.GetAttrs().AsMap()}}

	ev := audit.Event{TS: time.Now().UTC(), Tenant: tenant, Caller: claims.Subject, Subject: in.Subject,
		Action: in.Action, Resource: in.Resource, PolicyVersion: st.Active, Reason: "no active policy"}
	if st.Active != 0 {
		d, err := s.eval(ctx, tenant, st.Active, in)
		if err != nil {
			return nil, internal("evaluate policy", err)
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
		return nil, internal("append audit", err)
	}
	metrics.Checks.WithLabelValues(tenant, decisionLabel(ev.Allowed)).Inc()
	return &pb.CheckResponse{Allowed: ev.Allowed, Reason: ev.Reason, PolicyVersion: ev.PolicyVersion, AuditSeq: ev.Seq}, nil
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
	claims, err := requireScope(ctx, auth.ScopePolicyWrite)
	if err != nil {
		return nil, err
	}
	if _, err := policy.Compile(ctx, req.Rego); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	tenant := claims.Tenant
	p, created, err := s.store.PutPolicy(ctx, tenant, req.Rego, req.IdempotencyKey)
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
			st.Active, st.Shadow = p.Version, 0
		}
		if err := s.store.SetTenantState(ctx, tenant, st); err != nil {
			return nil, internal("set tenant state", err)
		}
		s.log.Info("policy stored", "tenant", tenant, "version", p.Version, "shadow", req.Shadow, "by", claims.Subject)
	}
	return &pb.PutPolicyResponse{Version: p.Version, Created: created, Shadow: st.Shadow == p.Version}, nil
}

func (s *Service) PromotePolicy(ctx context.Context, req *pb.PromotePolicyRequest) (*pb.PromotePolicyResponse, error) {
	claims, err := requireScope(ctx, auth.ScopePolicyWrite)
	if err != nil {
		return nil, err
	}
	tenant := claims.Tenant
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
