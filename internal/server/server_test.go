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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/store"
)

const allScopes = auth.ScopeCheck + " " + auth.ScopePolicyWrite + " " + auth.ScopeAuditRead

type env struct {
	iss  *auth.Issuer
	grpc pb.GatekeeperClient
	http *httptest.Server
}

// newEnv wires issuer -> verifier -> service -> in-process gRPC and HTTP listeners.
func newEnv(t *testing.T) *env {
	t.Helper()
	iss, err := auth.NewIssuer("https://issuer.test", "gatekeeper")
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(iss.JWKS))
	t.Cleanup(jwks.Close)
	v := auth.NewVerifier(iss.Name, "gatekeeper", jwks.URL)
	svc := New(store.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.UnaryInterceptor(UnaryAuth(v)))
	pb.RegisterGatekeeperServer(gs, svc)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	hs := httptest.NewServer(NewHTTPHandler(svc, v, nil))
	t.Cleanup(hs.Close)
	return &env{iss: iss, grpc: pb.NewGatekeeperClient(conn), http: hs}
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
