//go:build e2e

package e2e

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Real Envoy in front of a stand-in upstream, gatekeeper as its ext_authz
// gRPC service (deploy/envoy). Requests are allowed or denied by the tenant's
// Rego policy, every decision is in the audit chain, and stopping gatekeeper
// makes Envoy fail closed.
func TestEnvoyExtAuthz(t *testing.T) {
	gk, envoy := env("GK_HTTP", "http://localhost:18080"), env("ENVOY_URL", "http://localhost:10000")
	waitHTTP(t, gk+"/healthz", 60*time.Second)
	waitHTTP(t, envoy, 60*time.Second)

	admin := devToken(t, gk, "tenant=acme&scope="+url.QueryEscape("policy:write audit:read"))
	rego, err := os.ReadFile("../policies/http.rego")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"rego": string(rego)})
	if r := do(t, "PUT", gk+"/v1/policies", admin, string(body)); r.code != 200 {
		t.Fatalf("put policy: %d %s", r.code, r.body)
	}
	user := func(sub, roles string) string { return devToken(t, gk, "tenant=acme&sub="+sub+"&roles="+roles) }
	viewer, root, plain := user("viewer-1", "viewer"), user("admin-1", "admin"), user("user-1", "")
	stranger := devToken(t, gk, "tenant=globex&sub=x") // tenant with no policy

	cases := []struct {
		name, method, path, token string
		want                      int
	}{
		{"no token", "GET", "/docs/1", "", 401},
		{"forged token", "GET", "/docs/1", "a.b.c", 401},
		{"public read", "GET", "/public/readme", plain, 200},
		{"plain user private read", "GET", "/docs/1", plain, 403},
		{"viewer read", "GET", "/docs/1?rev=2", viewer, 200},
		{"viewer write", "POST", "/docs/1", viewer, 403},
		{"admin delete", "DELETE", "/docs/1", root, 200},
		{"tenant without policy", "GET", "/public/readme", stranger, 403},
	}
	audited := 0
	for _, c := range cases {
		// A client-supplied identity header must be overwritten, never trusted.
		r := do(t, c.method, envoy+c.path, c.token, "", "X-Gatekeeper-Subject", "spoofed")
		if r.code != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, r.code, c.want, r.body)
			continue
		}
		switch r.code {
		case 200:
			if r.body != "upstream ok\n" || r.hdr.Get("X-Gatekeeper-Audit-Seq") == "" {
				t.Errorf("%s: allowed response missing upstream body or audit seq: %v %q", c.name, r.hdr, r.body)
			}
			if sub := r.hdr.Get("X-Upstream-Saw-Subject"); sub == "spoofed" || sub == "" || r.hdr.Get("X-Upstream-Saw-Tenant") != "acme" {
				t.Errorf("%s: upstream saw subject %q tenant %q", c.name, sub, r.hdr.Get("X-Upstream-Saw-Tenant"))
			}
		case 403:
			if r.hdr.Get("X-Gatekeeper-Audit-Seq") == "" {
				t.Errorf("%s: denial not audited: %v", c.name, r.hdr)
			}
		}
		if r.code != 401 && c.token != stranger {
			audited++
		}
	}

	// The acme audit log holds exactly the proxied decisions, and the chain verifies.
	var log struct {
		Events []struct {
			Subject  struct{ ID string }
			Action   string
			Resource struct{ ID string }
			Allowed  bool
		}
	}
	r := do(t, "GET", gk+"/v1/audit?limit=100", admin, "")
	json.Unmarshal([]byte(r.body), &log)
	if len(log.Events) != audited {
		t.Fatalf("audit has %d events, want %d: %s", len(log.Events), audited, r.body)
	}
	if e := log.Events[len(log.Events)-1]; e.Subject.ID != "admin-1" || e.Action != "write" || e.Resource.ID != "/docs/1" || !e.Allowed {
		t.Fatalf("last audit event: %+v", e)
	}
	if r := do(t, "GET", gk+"/v1/audit/verify", admin, ""); r.code != 200 || !json.Valid([]byte(r.body)) {
		t.Fatalf("verify: %d %s", r.code, r.body)
	}

	// Fail closed: with gatekeeper stopped, Envoy denies even an admin.
	if f := os.Getenv("ENVOY_COMPOSE_FILE"); f != "" {
		if out, err := exec.Command("docker", "compose", "-f", f, "stop", "gatekeeper").CombinedOutput(); err != nil {
			t.Fatalf("stop gatekeeper: %v %s", err, out)
		}
		if r := do(t, "DELETE", envoy+"/docs/1", root, ""); r.code != 503 {
			t.Fatalf("gatekeeper down: %d, want 503 (fail closed)", r.code)
		}
	}
}
