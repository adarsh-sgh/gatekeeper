package gkctl

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/testserver"
	"github.com/adarsh-sgh/gatekeeper/sdk"
)

const (
	allowAll = "package gatekeeper\nallow := true\n"
	denyAll  = "package gatekeeper\nallow := false\n"
)

// The decK workflow end to end against a live server: diff a fresh file
// (drift), sync it, diff clean, detect out-of-band drift with a Rego diff,
// promote a shadow by moving it in the file, delete a tenant by removing it,
// and round-trip the state through dump.
func TestDiffSyncDump(t *testing.T) {
	srv := testserver.Start(t)
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		var out bytes.Buffer
		cmd := NewRoot()
		cmd.SetOut(&out)
		cmd.SetArgs(append(args, "--addr", srv.Addr, "--token", srv.AdminToken))
		err := cmd.ExecuteContext(context.Background())
		return out.String(), err
	}
	cfg := filepath.Join(dir, "gatekeeper.yaml")
	write("allow.rego", allowAll)
	write("deny.rego", denyAll)
	write("gatekeeper.yaml", `
tenants:
  - name: acme
    display_name: Acme
    policy: allow.rego
  - name: globex
    policy: deny.rego
    shadow: allow.rego
`)
	out, err := run("diff", "-f", cfg)
	if !errors.Is(err, ErrDrift) || !strings.Contains(out, "+ tenant acme") || !strings.Contains(out, "+ policy globex/shadow from allow.rego") ||
		!strings.Contains(out, "Summary: 5 to create, 0 to update, 0 to delete") {
		t.Fatalf("initial diff: err=%v\n%s", err, out)
	}
	if out, err = run("sync", "-f", cfg); err != nil || !strings.Contains(out, "Applied 5 changes") {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if out, err = run("diff", "-f", cfg); err != nil || !strings.Contains(out, "Summary: 0 to create, 0 to update, 0 to delete") {
		t.Fatalf("diff after sync: %v\n%s", err, out)
	}

	// The synced policy is what serves.
	cl, err := sdk.Dial(srv.Addr, sdk.Options{Token: srv.Token("svc", "acme", auth.ScopeCheck)})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	check := &pb.CheckRequest{Subject: &pb.Subject{Id: "u"}, Action: "read", Resource: &pb.Resource{Type: "doc"}}
	if r, err := cl.Check(context.Background(), check); err != nil || !r.Allowed {
		t.Fatalf("acme check after sync: %+v %v", r, err)
	}

	// Someone changes acme's policy behind gkctl's back.
	admin, _ := sdk.Dial(srv.Addr, sdk.Options{Token: srv.AdminToken})
	defer admin.Close()
	if _, err := admin.PutPolicy(context.Background(), &pb.PutPolicyRequest{Tenant: "acme", Rego: denyAll}); err != nil {
		t.Fatal(err)
	}
	out, err = run("diff", "-f", cfg)
	if !errors.Is(err, ErrDrift) || !strings.Contains(out, "~ policy acme/active from allow.rego") ||
		!strings.Contains(out, "-allow := false") || !strings.Contains(out, "+allow := true") {
		t.Fatalf("drift diff: err=%v\n%s", err, out)
	}

	// Promote globex's shadow by moving it into `policy`; drop acme entirely.
	write("gatekeeper.yaml", `
tenants:
  - name: globex
    display_name: Globex
    policy: allow.rego
`)
	out, err = run("sync", "-f", cfg)
	for _, want := range []string{"~ tenant globex", "^ policy globex/active: promote shadow v2", "- tenant acme (not in file)", "Summary: 0 to create, 2 to update, 1 to delete"} {
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("sync 2 missing %q: %v\n%s", want, err, out)
		}
	}
	g, err := admin.GetTenant(context.Background(), &pb.GetTenantRequest{Name: "globex"})
	if err != nil || g.ActiveVersion != 2 || g.ShadowVersion != 0 {
		t.Fatalf("promote kept version 2: %+v %v", g, err)
	}
	if r, err := cl.Check(context.Background(), check); err != nil || r.Allowed || r.Reason != "no active policy" {
		t.Fatalf("deleted tenant must fail closed: %+v %v", r, err)
	}

	// dump -> file -> diff is clean.
	dumpDir := t.TempDir()
	out, err = run("dump", "--dir", dumpDir)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dumpDir, "gatekeeper.yaml"), []byte(out), 0o644)
	if out, err = run("diff", "-f", filepath.Join(dumpDir, "gatekeeper.yaml")); err != nil {
		t.Fatalf("diff of dump: %v\n%s", err, out)
	}
}
