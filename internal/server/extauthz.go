package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/metrics"
	"github.com/adarsh-sgh/gatekeeper/internal/policy"
	"github.com/adarsh-sgh/gatekeeper/internal/ratelimit"
)

// ExtAuthzMethodPrefix is skipped by the gRPC auth interceptor: Envoy calls
// without a token of its own, and the decision is about the end user's bearer
// token forwarded in the HTTP request, which ExtAuthz verifies itself.
const ExtAuthzMethodPrefix = "/envoy.service.auth.v3.Authorization/"

// ExtAuthz implements Envoy's external authorization gRPC API on top of the
// same decide path as Check, so every proxied request is evaluated against
// the tenant's Rego policy and lands in the audit chain.
//
// Mapping: subject = token sub + roles, tenant = token tenant,
// action = "read" for GET/HEAD/OPTIONS and "write" otherwise,
// resource = {type: "http", id: path, attrs: {method, host, path}}.
type ExtAuthz struct {
	authv3.UnimplementedAuthorizationServer
	svc     *Service
	v       *auth.Verifier
	limiter *ratelimit.Limiter
}

func NewExtAuthz(svc *Service, o Options) *ExtAuthz {
	return &ExtAuthz{svc: svc, v: o.Verifier, limiter: o.Limiter}
}

func (a *ExtAuthz) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	h := req.GetAttributes().GetRequest().GetHttp()
	claims, err := verify(ctx, a.v, h.GetHeaders()["authorization"])
	if err != nil {
		return deny(codes.Unauthenticated, http.StatusUnauthorized, "unauthenticated", header("www-authenticate", "Bearer")), nil
	}
	setTenant(ctx, claims.Tenant)
	if a.limiter != nil {
		if ok, wait := a.limiter.Allow(claims.Tenant); !ok {
			metrics.RateLimited.WithLabelValues(claims.Tenant).Inc()
			return deny(codes.ResourceExhausted, http.StatusTooManyRequests, "rate limited",
				header("retry-after", strconv.Itoa(int(wait.Seconds())+1))), nil
		}
	}
	path, _, _ := strings.Cut(h.GetPath(), "?")
	action := "write"
	switch h.GetMethod() {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		action = "read"
	}
	ev, err := a.svc.decide(ctx, claims, policy.Input{Tenant: claims.Tenant, Action: action,
		Subject: audit.Subject{ID: claims.Subject, Roles: claims.Roles},
		Resource: audit.Resource{Type: "http", ID: path,
			Attrs: map[string]any{"method": h.GetMethod(), "host": h.GetHost(), "path": path}}})
	if err != nil {
		return nil, err // Envoy fails closed (failure_mode_allow: false)
	}
	seq := header("x-gatekeeper-audit-seq", strconv.FormatInt(ev.Seq, 10))
	if !ev.Allowed {
		return deny(codes.PermissionDenied, http.StatusForbidden, ev.Reason, seq, header("x-gatekeeper-reason", ev.Reason)), nil
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
			// Upstream learns who was authorised; a client-sent copy is overwritten.
			Headers: []*corev3.HeaderValueOption{header("x-gatekeeper-tenant", claims.Tenant), header("x-gatekeeper-subject", claims.Subject)},
			ResponseHeadersToAdd: []*corev3.HeaderValueOption{seq,
				header("x-gatekeeper-policy-version", strconv.FormatInt(ev.PolicyVersion, 10))},
		}},
	}, nil
}

func deny(c codes.Code, httpCode int, reason string, hdrs ...*corev3.HeaderValueOption) *authv3.CheckResponse {
	body, _ := json.Marshal(map[string]any{"allowed": false, "reason": reason})
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(c), Message: reason},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status:  &typev3.HttpStatus{Code: typev3.StatusCode(httpCode)},
			Headers: append(hdrs, header("content-type", "application/json")),
			Body:    string(body),
		}},
	}
}

func header(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: k, Value: v},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD}
}
