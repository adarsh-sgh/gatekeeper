package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/ratelimit"
	"github.com/adarsh-sgh/gatekeeper/internal/store"
)

const allScopes = auth.ScopeCheck + " " + auth.ScopePolicyWrite + " " + auth.ScopeAuditRead

type env struct {
	iss    *auth.Issuer
	grpc   pb.GatekeeperClient
	authz  authv3.AuthorizationClient
	http   *httptest.Server
	health *Health
}

// newEnv wires issuer -> verifier -> service -> in-process gRPC and HTTP listeners.
// The optional limiter is shared by both transports, as in main.
func newEnv(t *testing.T, limiter ...*ratelimit.Limiter) *env {
	t.Helper()
	iss, err := auth.NewIssuer("https://issuer.test", "gatekeeper")
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(iss.JWKS))
	t.Cleanup(jwks.Close)
	v := auth.NewVerifier(iss.Name, "gatekeeper", jwks.URL)
	st := store.NewMemory()
	svc := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	o := Options{Verifier: v, Health: NewHealth(st), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if len(limiter) > 0 {
		o.Limiter = limiter[0]
	}

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(GRPCInterceptors(o))
	pb.RegisterGatekeeperServer(gs, svc)
	authv3.RegisterAuthorizationServer(gs, NewExtAuthz(svc, o))
	o.Health.Register(gs)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	hs := httptest.NewServer(NewHTTPHandler(svc, o))
	t.Cleanup(hs.Close)
	return &env{iss: iss, grpc: pb.NewGatekeeperClient(conn), authz: authv3.NewAuthorizationClient(conn), http: hs, health: o.Health}
}

func (e *env) ctx(sub, tenant, scope string) context.Context {
	tok := e.iss.Mint(sub, tenant, nil, scope, time.Minute)
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+tok)
}

func attrs(t *testing.T, m map[string]any) *structpb.Struct {
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func code(err error) codes.Code { return status.Code(err) }

// The full lifecycle over gRPC: bootstrap policy, checks, shadow rollout with
// divergence logging, promote, idempotent replay, and a verifiable audit chain.
func TestShadowRolloutOverGRPC(t *testing.T) {
	e := newEnv(t)
	admin := e.ctx("ops", "acme", allScopes)
	example, err := os.ReadFile("../../policies/example.rego")
	if err != nil {
		t.Fatal(err)
	}
	req := func(sub, action string, res map[string]any) *pb.CheckRequest {
		return &pb.CheckRequest{Subject: &pb.Subject{Id: sub}, Action: action,
			Resource: &pb.Resource{Type: "doc", Id: "d1", Attrs: attrs(t, res)}}
	}

	// No policy yet: deny, but still audited.
	r, err := e.grpc.Check(admin, req("u1", "read", nil))
	if err != nil || r.Allowed || r.AuditSeq != 1 || r.PolicyVersion != 0 {
		t.Fatalf("check without policy: %+v err=%v", r, err)
	}

	// v1: example policy, active immediately.
	p, err := e.grpc.PutPolicy(admin, &pb.PutPolicyRequest{Rego: string(example), IdempotencyKey: "put-1"})
	if err != nil || p.Version != 1 || !p.Created || p.Shadow {
		t.Fatalf("put v1: %+v err=%v", p, err)
	}
	if r, _ = e.grpc.Check(admin, req("u1", "write", map[string]any{"owner": "u1"})); !r.Allowed || r.Reason != "owner" || r.PolicyVersion != 1 {
		t.Fatalf("owner write: %+v", r)
	}
	if r, _ = e.grpc.Check(admin, req("u2", "read", map[string]any{"public": true})); !r.Allowed {
		t.Fatalf("public read: %+v", r)
	}

	// v2 in shadow: public reads now require role "reader". Old decision must still be served.
	stricter := strings.Replace(string(example), `input.resource.attrs.public == true
	not input.subject.attrs.suspended`, `input.resource.attrs.public == true
	"reader" in input.subject.roles`, 1)
	if stricter == string(example) {
		t.Fatal("test edit to policy did not apply")
	}
	p, err = e.grpc.PutPolicy(admin, &pb.PutPolicyRequest{Rego: stricter, IdempotencyKey: "put-2", Shadow: true})
	if err != nil || p.Version != 2 || !p.Shadow {
		t.Fatalf("put v2 shadow: %+v err=%v", p, err)
	}
	r, _ = e.grpc.Check(admin, req("u2", "read", map[string]any{"public": true}))
	if !r.Allowed || r.PolicyVersion != 1 {
		t.Fatalf("shadow must not change served decision: %+v", r)
	}
	evs, _ := e.grpc.ListAuditEvents(admin, &pb.ListAuditEventsRequest{AfterSeq: r.AuditSeq - 1, Limit: 1})
	last := evs.Events[0]
	if last.ShadowVersion != 2 || last.ShadowAllowed || !last.ShadowDiverged {
		t.Fatalf("divergence not logged: %+v", last)
	}

	// Replaying the same idempotency key is a no-op; a different body under it is a conflict.
	if p, _ = e.grpc.PutPolicy(admin, &pb.PutPolicyRequest{Rego: stricter, IdempotencyKey: "put-2", Shadow: true}); p.Created || p.Version != 2 {
		t.Fatalf("replay: %+v", p)
	}
	if _, err = e.grpc.PutPolicy(admin, &pb.PutPolicyRequest{Rego: string(example), IdempotencyKey: "put-2"}); code(err) != codes.FailedPrecondition {
		t.Fatalf("mismatched replay: %v", err)
	}
	if _, err = e.grpc.PutPolicy(admin, &pb.PutPolicyRequest{Rego: "package gatekeeper\nallow if {"}); code(err) != codes.InvalidArgument {
		t.Fatalf("bad rego: %v", err)
	}

	// Promote v2: the stricter rule now serves.
	if pr, err := e.grpc.PromotePolicy(admin, &pb.PromotePolicyRequest{Version: 2}); err != nil || pr.ActiveVersion != 2 {
		t.Fatalf("promote: %+v err=%v", pr, err)
	}
	if _, err = e.grpc.PromotePolicy(admin, &pb.PromotePolicyRequest{Version: 9}); code(err) != codes.NotFound {
		t.Fatalf("promote missing: %v", err)
	}
	if r, _ = e.grpc.Check(admin, req("u2", "read", map[string]any{"public": true})); r.Allowed || r.PolicyVersion != 2 {
		t.Fatalf("after promote: %+v", r)
	}
	if r, _ = e.grpc.Check(admin, &pb.CheckRequest{Subject: &pb.Subject{Id: "u2", Roles: []string{"reader"}}, Action: "read",
		Resource: &pb.Resource{Type: "doc", Attrs: attrs(t, map[string]any{"public": true})}}); !r.Allowed {
		t.Fatalf("reader after promote: %+v", r)
	}

	// Tenants are isolated: another tenant sees no policy and an empty audit log.
	other := e.ctx("ops", "globex", allScopes)
	if r, _ = e.grpc.Check(other, req("u1", "write", map[string]any{"owner": "u1"})); r.Allowed || r.AuditSeq != 1 {
		t.Fatalf("tenant isolation: %+v", r)
	}

	vr, err := e.grpc.VerifyAuditChain(admin, &pb.VerifyAuditChainRequest{})
	if err != nil || !vr.Ok || vr.EventsChecked != 6 {
		t.Fatalf("verify: %+v err=%v", vr, err)
	}
	if evs, _ = e.grpc.ListAuditEvents(admin, &pb.ListAuditEventsRequest{}); len(evs.Events) != 6 || evs.Events[0].Caller != "ops" {
		t.Fatalf("list: %d events, first caller %q", len(evs.Events), evs.Events[0].Caller)
	}
}

func TestAuthAndScopes(t *testing.T) {
	e := newEnv(t)
	check := &pb.CheckRequest{Subject: &pb.Subject{Id: "u"}, Action: "read", Resource: &pb.Resource{Type: "doc"}}
	cases := []struct {
		name string
		ctx  context.Context
		call func(context.Context) error
		want codes.Code
	}{
		{"no token", context.Background(), func(c context.Context) error { _, err := e.grpc.Check(c, check); return err }, codes.Unauthenticated},
		{"forged token", metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer x.y.z"),
			func(c context.Context) error { _, err := e.grpc.Check(c, check); return err }, codes.Unauthenticated},
		{"check scope only cannot write", e.ctx("svc", "acme", auth.ScopeCheck),
			func(c context.Context) error {
				_, err := e.grpc.PutPolicy(c, &pb.PutPolicyRequest{Rego: "package gatekeeper"})
				return err
			}, codes.PermissionDenied},
		{"check scope only cannot read audit", e.ctx("svc", "acme", auth.ScopeCheck),
			func(c context.Context) error {
				_, err := e.grpc.ListAuditEvents(c, &pb.ListAuditEventsRequest{})
				return err
			}, codes.PermissionDenied},
		{"missing fields", e.ctx("svc", "acme", auth.ScopeCheck),
			func(c context.Context) error { _, err := e.grpc.Check(c, &pb.CheckRequest{Action: "read"}); return err }, codes.InvalidArgument},
		{"ok", e.ctx("svc", "acme", auth.ScopeCheck), func(c context.Context) error { _, err := e.grpc.Check(c, check); return err }, codes.OK},
	}
	for _, tc := range cases {
		if got := code(tc.call(tc.ctx)); got != tc.want {
			t.Errorf("%s: code %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Same service over the JSON/HTTP mirror, including the Idempotency-Key header and error mapping.
func TestHTTPMirror(t *testing.T) {
	e := newEnv(t)
	tok := e.iss.Mint("ops", "acme", nil, allScopes, time.Minute)
	do := func(method, path, body string, hdr map[string]string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, e.http.URL+path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	if st, out := do("PUT", "/v1/policies", `{"rego":"package gatekeeper\nallow if input.action == \"read\""}`, map[string]string{"Idempotency-Key": "h1"}); st != 200 || out["version"] != "1" || out["created"] != true {
		t.Fatalf("put: %d %v", st, out)
	}
	if st, out := do("PUT", "/v1/policies", `{"rego":"package gatekeeper\nallow if input.action == \"read\""}`, map[string]string{"Idempotency-Key": "h1"}); st != 200 || out["created"] != false {
		t.Fatalf("put replay: %d %v", st, out)
	}
	if st, out := do("POST", "/v1/check", `{"subject":{"id":"u"},"action":"read","resource":{"type":"doc"}}`, nil); st != 200 || out["allowed"] != true {
		t.Fatalf("check: %d %v", st, out)
	}
	if st, out := do("POST", "/v1/check", `{"subject":{"id":"u"},"action":"write","resource":{"type":"doc"}}`, nil); st != 200 || out["allowed"] != false {
		t.Fatalf("check deny: %d %v", st, out)
	}
	if st, out := do("GET", "/v1/audit?limit=1&after_seq=1", "", nil); st != 200 || len(out["events"].([]any)) != 1 {
		t.Fatalf("audit: %d %v", st, out)
	}
	if st, out := do("GET", "/v1/audit/verify", "", nil); st != 200 || out["ok"] != true || out["eventsChecked"] != "2" {
		t.Fatalf("verify: %d %v", st, out)
	}
	if st, _ := do("POST", "/v1/policies/7/promote", "", nil); st != 404 {
		t.Fatalf("promote missing: %d", st)
	}
	if st, _ := do("POST", "/v1/check", `{"action":`, nil); st != 400 {
		t.Fatalf("malformed json: %d", st)
	}
	resp, _ := http.Get(e.http.URL + "/v1/audit")
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated: %d", resp.StatusCode)
	}
	resp, _ = http.Get(e.http.URL + "/metrics")
	b, _ := io.ReadAll(resp.Body)
	for _, m := range []string{"gatekeeper_checks_total", "gatekeeper_auth_failures_total"} {
		if !strings.Contains(string(b), m) {
			t.Errorf("metric %s not exposed", m)
		}
	}
}

// Per-tenant limiter over both transports: one tenant's burst exhausts only
// its own bucket; the caller gets 429 / ResourceExhausted with a Retry-After.
func TestRateLimitPerTenant(t *testing.T) {
	e := newEnv(t, ratelimit.New(1, 2)) // 1/s, burst 2
	check := &pb.CheckRequest{Subject: &pb.Subject{Id: "u"}, Action: "read", Resource: &pb.Resource{Type: "doc"}}
	acme := e.ctx("svc", "acme", auth.ScopeCheck)
	for i := 0; i < 2; i++ {
		if _, err := e.grpc.Check(acme, check); err != nil {
			t.Fatalf("burst %d: %v", i, err)
		}
	}
	var hdr metadata.MD
	if _, err := e.grpc.Check(acme, check, grpc.Header(&hdr)); code(err) != codes.ResourceExhausted || len(hdr.Get("retry-after")) == 0 {
		t.Fatalf("3rd grpc call: err=%v hdr=%v", err, hdr)
	}
	if _, err := e.grpc.Check(e.ctx("svc", "globex", auth.ScopeCheck), check); err != nil {
		t.Fatalf("other tenant limited: %v", err)
	}

	req, _ := http.NewRequest("POST", e.http.URL+"/v1/check", strings.NewReader(`{"subject":{"id":"u"},"action":"read","resource":{"type":"doc"}}`))
	req.Header.Set("Authorization", "Bearer "+e.iss.Mint("svc", "acme", nil, auth.ScopeCheck, time.Minute))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("http over limit: %v %v", resp.StatusCode, err)
	}
	resp, _ = http.Get(e.http.URL + "/metrics")
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `gatekeeper_ratelimited_total{tenant="acme"} 2`) {
		t.Errorf("ratelimited metric not counted: %s", b)
	}
}

// Request ids are honoured when given and generated otherwise, on both transports;
// readiness follows the drain flag.
func TestRequestIDsAndReadiness(t *testing.T) {
	e := newEnv(t)
	check := &pb.CheckRequest{Subject: &pb.Subject{Id: "u"}, Action: "read", Resource: &pb.Resource{Type: "doc"}}
	var hdr metadata.MD
	ctx := metadata.AppendToOutgoingContext(e.ctx("svc", "acme", auth.ScopeCheck), RequestIDHeader, "req-42")
	if _, err := e.grpc.Check(ctx, check, grpc.Header(&hdr)); err != nil || hdr.Get(RequestIDHeader)[0] != "req-42" {
		t.Fatalf("grpc echo: %v %v", hdr, err)
	}
	hdr = nil
	if _, err := e.grpc.Check(e.ctx("svc", "acme", auth.ScopeCheck), check, grpc.Header(&hdr)); err != nil || len(hdr.Get(RequestIDHeader)[0]) != 16 {
		t.Fatalf("grpc generated id: %v %v", hdr, err)
	}
	resp, _ := http.Get(e.http.URL + "/v1/audit") // 401, still gets an id
	if resp.StatusCode != 401 || len(resp.Header.Get(RequestIDHeader)) != 16 {
		t.Fatalf("http generated id: %d %q", resp.StatusCode, resp.Header.Get(RequestIDHeader))
	}

	if resp, _ = http.Get(e.http.URL + "/readyz"); resp.StatusCode != 200 {
		t.Fatalf("readyz: %d", resp.StatusCode)
	}
	e.health.Drain()
	if resp, _ = http.Get(e.http.URL + "/readyz"); resp.StatusCode != 503 {
		t.Fatalf("readyz while draining: %d", resp.StatusCode)
	}
	if _, err := e.grpc.Check(e.ctx("svc", "acme", auth.ScopeCheck), check); err != nil {
		t.Fatalf("draining must not reject requests: %v", err)
	}
}

// Tenant registry and cross-tenant admin: a tenants:admin token manages any
// tenant's policies via the tenant field; a plain token cannot. Disabling a
// tenant and unsetting its policy both fail closed, and deleting it clears
// the rollout. The same RPCs answer on the generated HTTP routes.
func TestTenantAdmin(t *testing.T) {
	e := newEnv(t)
	root := e.ctx("ops", "root", allScopes+" "+auth.ScopeTenantAdmin)
	acme := e.ctx("svc", "acme", allScopes)
	check := &pb.CheckRequest{Subject: &pb.Subject{Id: "u"}, Action: "read", Resource: &pb.Resource{Type: "doc"}}

	if _, err := e.grpc.PutTenant(root, &pb.PutTenantRequest{Tenant: &pb.Tenant{Name: "Bad Name"}}); code(err) != codes.InvalidArgument {
		t.Fatalf("bad name: %v", err)
	}
	if _, err := e.grpc.PutTenant(acme, &pb.PutTenantRequest{Tenant: &pb.Tenant{Name: "acme"}}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin put tenant: %v", err)
	}
	if _, err := e.grpc.PutPolicy(acme, &pb.PutPolicyRequest{Tenant: "globex", Rego: "package gatekeeper"}); code(err) != codes.PermissionDenied {
		t.Fatalf("cross-tenant without admin: %v", err)
	}
	tn, err := e.grpc.PutTenant(root, &pb.PutTenantRequest{Tenant: &pb.Tenant{Name: "acme", DisplayName: "Acme"}})
	if err != nil || tn.DisplayName != "Acme" || tn.CreateTime == nil {
		t.Fatalf("put tenant: %+v %v", tn, err)
	}
	p, err := e.grpc.PutPolicy(root, &pb.PutPolicyRequest{Tenant: "acme", Rego: "package gatekeeper\nallow := true"})
	if err != nil || p.Version != 1 {
		t.Fatalf("admin put policy for acme: %+v %v", p, err)
	}
	if got, err := e.grpc.GetPolicy(root, &pb.GetPolicyRequest{Tenant: "acme", Version: 1}); err != nil || !strings.Contains(got.Rego, "allow := true") {
		t.Fatalf("get policy: %+v %v", got, err)
	}
	if r, _ := e.grpc.Check(acme, check); !r.Allowed {
		t.Fatalf("acme check after admin put: %+v", r)
	}
	if tn, _ = e.grpc.GetTenant(root, &pb.GetTenantRequest{Name: "acme"}); tn.ActiveVersion != 1 {
		t.Fatalf("tenant rollout state: %+v", tn)
	}

	// Kill switch, then re-enable.
	e.grpc.PutTenant(root, &pb.PutTenantRequest{Tenant: &pb.Tenant{Name: "acme", Disabled: true}})
	if r, _ := e.grpc.Check(acme, check); r.Allowed || r.Reason != "tenant disabled" || r.AuditSeq == 0 {
		t.Fatalf("disabled tenant must deny, audited: %+v", r)
	}
	e.grpc.PutTenant(root, &pb.PutTenantRequest{Tenant: &pb.Tenant{Name: "acme"}})
	if u, err := e.grpc.UnsetPolicy(root, &pb.UnsetPolicyRequest{Tenant: "acme"}); err != nil || u.ActiveVersion != 0 {
		t.Fatalf("unset: %+v %v", u, err)
	}
	if r, _ := e.grpc.Check(acme, check); r.Allowed || r.Reason != "no active policy" {
		t.Fatalf("unset must fail closed: %+v", r)
	}

	// HTTP: generated routes for the registry.
	tok := e.iss.Mint("ops", "root", nil, auth.ScopeTenantAdmin, time.Minute)
	req, _ := http.NewRequest("PUT", e.http.URL+"/v1/tenants/globex", strings.NewReader(`{"displayName":"Globex"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("http put tenant: %v %v", resp.StatusCode, err)
	}
	req, _ = http.NewRequest("GET", e.http.URL+"/v1/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, _ := http.DefaultClient.Do(req)
	var list struct{ Tenants []struct{ Name, DisplayName string } }
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list.Tenants) != 2 || list.Tenants[1].Name != "globex" || list.Tenants[1].DisplayName != "Globex" {
		t.Fatalf("http list tenants: %+v", list)
	}

	if _, err := e.grpc.DeleteTenant(root, &pb.DeleteTenantRequest{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.grpc.GetTenant(root, &pb.GetTenantRequest{Name: "acme"}); code(err) != codes.NotFound {
		t.Fatalf("deleted tenant: %v", err)
	}
	if _, err := e.grpc.DeleteTenant(root, &pb.DeleteTenantRequest{Name: "acme"}); code(err) != codes.NotFound {
		t.Fatalf("double delete: %v", err)
	}
}

// Envoy ext_authz adapter: the forwarded end-user token picks tenant and
// subject, the HTTP method/path become action/resource, and the decision is
// audited like any Check.
func TestExtAuthz(t *testing.T) {
	e := newEnv(t)
	admin := e.ctx("ops", "acme", allScopes)
	rego, err := os.ReadFile("../../policies/http.rego")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.grpc.PutPolicy(admin, &pb.PutPolicyRequest{Rego: string(rego)}); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, sub string, roles ...string) *authv3.CheckResponse {
		t.Helper()
		hdrs := map[string]string{}
		if sub != "" {
			hdrs["authorization"] = "Bearer " + e.iss.Mint(sub, "acme", roles, "", time.Minute)
		}
		r, err := e.authz.Check(context.Background(), &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
				Method: method, Path: path, Host: "api.test", Headers: hdrs}}}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	httpStatus := func(r *authv3.CheckResponse) int {
		if r.GetOkResponse() != nil {
			return 200
		}
		return int(r.GetDeniedResponse().GetStatus().GetCode())
	}
	cases := []struct {
		method, path, sub string
		roles             []string
		want              int
	}{
		{"GET", "/docs/1", "", nil, 401},
		{"GET", "/public/readme?x=1", "u1", nil, 200},
		{"GET", "/docs/1", "u1", nil, 403},
		{"GET", "/docs/1", "u2", []string{"viewer"}, 200},
		{"DELETE", "/docs/1", "u2", []string{"viewer"}, 403},
		{"DELETE", "/docs/1", "u3", []string{"admin"}, 200},
	}
	for _, c := range cases {
		if got := httpStatus(call(c.method, c.path, c.sub, c.roles...)); got != c.want {
			t.Errorf("%s %s as %s%v: %d, want %d", c.method, c.path, c.sub, c.roles, got, c.want)
		}
	}
	evs, _ := e.grpc.ListAuditEvents(admin, &pb.ListAuditEventsRequest{})
	if len(evs.Events) != 5 { // the 401 never reaches policy
		t.Fatalf("audited %d ext_authz decisions, want 5", len(evs.Events))
	}
	if last := evs.Events[4]; last.Subject.Id != "u3" || last.Action != "write" || last.Resource.Id != "/docs/1" || !last.Allowed {
		t.Fatalf("last audit event: %+v", last)
	}
	if public := evs.Events[0]; public.Resource.Id != "/public/readme" {
		t.Fatalf("query string must not reach the resource id: %q", public.Resource.Id)
	}
}
