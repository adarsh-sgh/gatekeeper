package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/adarsh-sgh/gatekeeper/internal/jwks"
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
	v.keys = jwks.New("http://127.0.0.1:1/unreachable")
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

// Two-phase rotation: a verifier that refreshes on MaxAge picks up the next
// key before it signs anything, so the switch costs no extra JWKS fetch and
// tokens signed by the old key keep verifying. Revocation beats the cache.
func TestIssuerRotationAndRevocation(t *testing.T) {
	iss, err := NewIssuer("https://issuer.test", "gatekeeper")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); iss.JWKS(w, r) }))
	defer srv.Close()
	ctx := context.Background()
	now := time.Now()
	v := NewVerifier(iss.Name, "gatekeeper", srv.URL)
	v.CacheTTL = 0
	v.keys.Now = func() time.Time { return now }

	oldTok := iss.Mint("a", "acme", nil, "", time.Hour)
	if _, err := v.Verify(ctx, oldTok); err != nil || hits.Load() != 1 {
		t.Fatalf("first verify: %v, fetches=%d", err, hits.Load())
	}
	oldKid := iss.Kid()
	if err := iss.PrepareNext(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(v.keys.MaxAge + time.Second) // cache ages out; next lookup refreshes and learns the next key
	if _, err := v.Verify(ctx, oldTok); err != nil || hits.Load() != 2 {
		t.Fatalf("refresh: %v, fetches=%d", err, hits.Load())
	}
	if err := iss.Rotate(time.Hour); err != nil || iss.Kid() == oldKid {
		t.Fatalf("rotate: %v", err)
	}
	newTok := iss.Mint("b", "acme", nil, "", time.Hour)
	for _, tok := range []string{newTok, oldTok} {
		if _, err := v.Verify(ctx, tok); err != nil {
			t.Fatalf("after rotation: %v", err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("switch to a pre-published key cost %d extra fetches", hits.Load()-2)
	}

	// Revocation: by jti, and by sid for every token of a session.
	v.CacheTTL = time.Minute
	v.Revoked = NewRevocationList()
	sess := iss.MintClaims(Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "c"}, Tenant: "acme", SID: "fam-1"}, time.Hour)
	for _, tok := range []string{newTok, sess} {
		if _, err := v.Verify(ctx, tok); err != nil { // now cached
			t.Fatal(err)
		}
	}
	nc, _ := v.Verify(ctx, newTok)
	v.Revoked.Revoke(nc.ID, nc.ExpiresAt.Time)
	v.Revoked.Revoke("fam-1", time.Now().Add(time.Hour))
	for _, tok := range []string{newTok, sess} {
		if _, err := v.Verify(ctx, tok); err != ErrRevoked {
			t.Errorf("revoked token: err=%v", err)
		}
	}
	if _, err := v.Verify(ctx, oldTok); err != nil {
		t.Errorf("unrelated token: %v", err)
	}
}
