package policy

import (
	"context"
	"os"
	"testing"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

func TestExamplePolicyDecisions(t *testing.T) {
	src, err := os.ReadFile("../../policies/example.rego")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := Compile(ctx, string(src))
	if err != nil {
		t.Fatal(err)
	}
	doc := func(attrs map[string]any) audit.Resource { return audit.Resource{Type: "doc", ID: "d1", Attrs: attrs} }
	cases := []struct {
		name   string
		in     Input
		allow  bool
		reason string
	}{
		{"admin", Input{Subject: audit.Subject{ID: "a", Roles: []string{"admin"}}, Action: "delete", Resource: doc(nil)}, true, "role:admin"},
		{"owner write", Input{Subject: audit.Subject{ID: "u1"}, Action: "write", Resource: doc(map[string]any{"owner": "u1"})}, true, "owner"},
		{"owner delete denied", Input{Subject: audit.Subject{ID: "u1"}, Action: "delete", Resource: doc(map[string]any{"owner": "u1"})}, false, "owner"},
		{"public read", Input{Subject: audit.Subject{ID: "u2"}, Action: "read", Resource: doc(map[string]any{"public": true, "owner": "u1"})}, true, "public"},
		{"suspended public read", Input{Subject: audit.Subject{ID: "u2", Attrs: map[string]any{"suspended": true}}, Action: "read", Resource: doc(map[string]any{"public": true})}, false, "public,suspended"},
		{"stranger", Input{Subject: audit.Subject{ID: "u3"}, Action: "read", Resource: doc(map[string]any{"owner": "u1"})}, false, ""},
	}
	for _, tc := range cases {
		d, err := c.Eval(ctx, tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if d.Allowed != tc.allow || d.Reason != tc.reason {
			t.Errorf("%s: got (%v, %q) want (%v, %q)", tc.name, d.Allowed, d.Reason, tc.allow, tc.reason)
		}
	}
}

func TestCompileRejectsBadPolicyAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	if _, err := Compile(ctx, "package gatekeeper\nallow if { input.x ="); err == nil {
		t.Fatal("expected syntax error")
	}
	// Wrong package: data.gatekeeper is undefined -> deny.
	c, err := Compile(ctx, "package other\nallow := true")
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := c.Eval(ctx, Input{}); d.Allowed {
		t.Fatal("undefined document must deny")
	}
	// Cache compiles once per (tenant, version).
	loads := 0
	cache := NewCache()
	for range 3 {
		if _, err := cache.Get(ctx, "t", 1, func() (string, error) { loads++; return "package gatekeeper\nallow := true", nil }); err != nil {
			t.Fatal(err)
		}
	}
	if loads != 1 {
		t.Fatalf("loads = %d, want 1", loads)
	}
}
