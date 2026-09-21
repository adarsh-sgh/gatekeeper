package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifierAgainstIssuer(t *testing.T) {
	iss, err := NewIssuer("https://issuer.test", "gatekeeper")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(iss.JWKS))
	defer srv.Close()
	ctx := context.Background()

	v := NewVerifier("https://issuer.test", "gatekeeper", srv.URL)
	c, err := v.Verify(ctx, iss.Mint("alice", "acme", []string{"admin"}, "policy:check policy:write", time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "alice" || c.Tenant != "acme" || !c.HasScope(ScopePolicyWrite) || c.HasScope(ScopeAuditRead) {
		t.Fatalf("claims = %+v", c)
	}

	bad := map[string]string{
		"expired":   iss.Mint("a", "acme", nil, "", -2*time.Minute),
		"no tenant": iss.Mint("a", "", nil, "", time.Minute),
		"garbage":   "not.a.jwt",
	}
	for name, tok := range bad {
		if _, err := v.Verify(ctx, tok); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := NewVerifier("https://issuer.test", "other", srv.URL).Verify(ctx, iss.Mint("a", "acme", nil, "", time.Minute)); err == nil {
		t.Error("wrong audience accepted")
	}
	if _, err := NewVerifier("https://evil.test", "gatekeeper", srv.URL).Verify(ctx, iss.Mint("a", "acme", nil, "", time.Minute)); err == nil {
		t.Error("wrong issuer accepted")
	}

	// A token from a different key with the same issuer name must be rejected
	// (JWKS is the trust anchor, not the iss string).
	other, _ := NewIssuer("https://issuer.test", "gatekeeper")
	if _, err := v.Verify(ctx, other.Mint("a", "acme", nil, "", time.Minute)); err == nil {
		t.Error("token signed by unknown key accepted")
	}

	// Cached verdicts: a seen token passes without its key, an unseen one does not;
	// a zero TTL disables the cache.
	tok := iss.Mint("bob", "acme", nil, "", time.Minute)
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	clear(v.keys)
	v.lastFetch = time.Now() // suppress JWKS refetch
	v.mu.Unlock()
	if c, err := v.Verify(ctx, tok); err != nil || c.Subject != "bob" {
		t.Errorf("cached token: %+v %v", c, err)
	}
	if _, err := v.Verify(ctx, iss.Mint("carol", "acme", nil, "", time.Minute)); err == nil {
		t.Error("unseen token verified without a key")
	}
	v.CacheTTL = 0
	if _, err := v.Verify(ctx, tok); err == nil {
		t.Error("cache served with TTL 0")
	}
}
