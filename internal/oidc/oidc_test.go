package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/oidc"
	"github.com/adarsh-sgh/gatekeeper/internal/oidc/oidctest"
)

func newRP(t testing.TB, idp *oidctest.IdP, vc oidc.ValidatorConfig) *oidc.RP {
	t.Helper()
	rp, err := oidc.New(context.Background(), oidc.Config{Issuer: idp.Issuer, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret,
		RedirectURL: "https://app.test/_gk/oidc/callback", Scopes: []string{"email"}, HTTPClient: idp.Client(), Validator: vc})
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// authorize follows AuthCodeURL to the IdP and returns the code it redirects back with.
func authorize(t *testing.T, idp *oidctest.IdP, authURL string) (code, state string) {
	t.Helper()
	c := idp.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %v", resp.StatusCode, err)
	}
	return loc.Query().Get("code"), loc.Query().Get("state")
}

// The whole login: discovery, PKCE S256, state and nonce, code exchange and
// id_token validation; then the ways a callback must fail.
func TestAuthCodeFlow(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	ctx := context.Background()
	rp := newRP(t, idp, oidc.ValidatorConfig{})

	authURL, state := rp.AuthCodeURL("/docs/1")
	q := must(url.Parse(authURL)).Query()
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("nonce") == "" || q.Get("scope") != "openid email" {
		t.Fatalf("auth url: %s", authURL)
	}
	code, gotState := authorize(t, idp, authURL)
	if gotState != state {
		t.Fatalf("state %q != %q", gotState, state)
	}
	res, err := rp.Exchange(ctx, state, code)
	if err != nil {
		t.Fatal(err)
	}
	if res.IDToken.Subject != "alice" || res.IDToken.String("email") != "alice@example.org" ||
		strings.Join(res.IDToken.Strings("groups"), ",") != "eng" || res.ReturnTo != "/docs/1" {
		t.Fatalf("result: %+v", res.IDToken)
	}
	if _, err := rp.Exchange(ctx, state, code); !errors.Is(err, oidc.ErrState) {
		t.Errorf("replayed callback: %v", err)
	}
	if _, err := rp.Exchange(ctx, "forged", code); !errors.Is(err, oidc.ErrState) {
		t.Errorf("unknown state: %v", err)
	}

	// A stolen code is useless without its verifier: redeeming it under
	// another login's state sends the wrong code_verifier.
	url1, _ := rp.AuthCodeURL("/")
	stolen, _ := authorize(t, idp, url1)
	_, state2 := rp.AuthCodeURL("/")
	if _, err := rp.Exchange(ctx, state2, stolen); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("code redeemed with wrong PKCE verifier: %v", err)
	}

	// An id_token minted for a different login (nonce) is rejected.
	idp.NonceOverride = "someone-elses-nonce"
	u, s := rp.AuthCodeURL("/")
	c, _ := authorize(t, idp, u)
	if _, err := rp.Exchange(ctx, s, c); !errors.Is(err, oidc.ErrNonce) {
		t.Errorf("nonce mismatch: %v", err)
	}

	// Discovery must return exactly the configured issuer.
	if _, err := oidc.New(ctx, oidc.Config{Issuer: idp.Issuer + "/", ClientID: "x", HTTPClient: idp.Client()}); err == nil {
		t.Error("issuer mismatch accepted by discovery")
	}
}

// Every id_token check with its failure: clock skew inside and outside the
// leeway, iss/aud/azp, nonce, alg confusion, malformed input, revocation.
func TestIDTokenValidation(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	ctx := context.Background()
	now := time.Now()
	revoked := auth.NewRevocationList()
	rp := newRP(t, idp, oidc.ValidatorConfig{Leeway: 30 * time.Second, Now: func() time.Time { return now }, Revoked: revoked})
	v := rp.Validator()
	revoked.Revoke("revoked-jti", now.Add(time.Hour))

	claims := func(mut func(jwt.MapClaims)) jwt.MapClaims {
		c := idp.Claims("alice", "n-1")
		c["iat"], c["exp"] = now.Unix(), now.Add(5*time.Minute).Unix()
		if mut != nil {
			mut(c)
		}
		return c
	}
	signed := func(mut func(jwt.MapClaims)) string { return idp.Sign(claims(mut)) }
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: must(x509.MarshalPKIXPublicKey(&idp.Key().PublicKey))})
	kidOf := func(tok string) string {
		p, _, _ := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
		return p.Header["kid"].(string)
	}
	realKid := kidOf(signed(nil))
	sign := func(method jwt.SigningMethod, key any, kid string) string {
		tok := jwt.NewWithClaims(method, claims(nil))
		tok.Header["kid"] = kid
		return must(tok.SignedString(key))
	}
	ecKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	otherRSA := must(rsa.GenerateKey(rand.Reader, 2048))
	valid := signed(nil)
	parts := strings.Split(valid, ".")
	forgedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + idp.Issuer + `","aud":"gatekeeper","sub":"admin","nonce":"n-1","iat":` +
		itoa(now.Unix()) + `,"exp":` + itoa(now.Add(time.Hour).Unix()) + `}`))

	cases := []struct {
		name, token, nonce string
		ok                 bool
	}{
		{"valid", valid, "n-1", true},
		{"expired within leeway", signed(func(c jwt.MapClaims) { c["exp"] = now.Add(-20 * time.Second).Unix() }), "n-1", true},
		{"expired beyond leeway", signed(func(c jwt.MapClaims) { c["exp"] = now.Add(-2 * time.Minute).Unix() }), "n-1", false},
		{"iat ahead within leeway (IdP clock fast)", signed(func(c jwt.MapClaims) { c["iat"] = now.Add(20 * time.Second).Unix() }), "n-1", true},
		{"iat ahead beyond leeway", signed(func(c jwt.MapClaims) { c["iat"] = now.Add(2 * time.Minute).Unix() }), "n-1", false},
		{"nbf beyond leeway", signed(func(c jwt.MapClaims) { c["nbf"] = now.Add(2 * time.Minute).Unix() }), "n-1", false},
		{"no exp", signed(func(c jwt.MapClaims) { delete(c, "exp") }), "n-1", false},
		{"no iat", signed(func(c jwt.MapClaims) { delete(c, "iat") }), "n-1", false},
		{"wrong issuer", signed(func(c jwt.MapClaims) { c["iss"] = "https://evil.test" }), "n-1", false},
		{"wrong audience", signed(func(c jwt.MapClaims) { c["aud"] = "other-client" }), "n-1", false},
		{"multi aud without azp", signed(func(c jwt.MapClaims) { c["aud"] = []string{"gatekeeper", "other"} }), "n-1", false},
		{"multi aud with azp", signed(func(c jwt.MapClaims) { c["aud"], c["azp"] = []string{"gatekeeper", "other"}, "gatekeeper" }), "n-1", true},
		{"azp is another client", signed(func(c jwt.MapClaims) { c["azp"] = "other" }), "n-1", false},
		{"nonce mismatch", valid, "n-2", false},
		{"revoked jti", signed(func(c jwt.MapClaims) { c["jti"] = "revoked-jti" }), "n-1", false},
		{"alg none", must(jwt.NewWithClaims(jwt.SigningMethodNone, claims(nil)).SignedString(jwt.UnsafeAllowNoneSignatureType)), "n-1", false},
		{"HS256 keyed with the IdP public key", sign(jwt.SigningMethodHS256, pubPEM, realKid), "n-1", false},
		{"RS512 not allowlisted", sign(jwt.SigningMethodRS512, idp.Key(), realKid), "n-1", false},
		{"ES256 under an RSA kid", sign(jwt.SigningMethodES256, ecKey, realKid), "n-1", false},
		{"unknown key, forged kid", sign(jwt.SigningMethodRS256, otherRSA, "forged"), "n-1", false},
		{"unknown key, real kid", sign(jwt.SigningMethodRS256, otherRSA, realKid), "n-1", false},
		{"tampered payload", parts[0] + "." + forgedPayload + "." + parts[2], "n-1", false},
		{"truncated signature", valid[:len(valid)-10], "n-1", false},
		{"two segments", parts[0] + "." + parts[1], "n-1", false},
		{"garbage", "a.b.c", "n-1", false},
		{"empty", "", "n-1", false},
	}
	for _, tc := range cases {
		_, err := v.Validate(ctx, tc.token, tc.nonce)
		if (err == nil) != tc.ok {
			t.Errorf("%s: ok=%v, err=%v", tc.name, tc.ok, err)
		}
	}
	for _, alg := range []string{"none", "HS256"} {
		if _, err := oidc.NewValidator(oidc.ValidatorConfig{Algs: []string{"RS256", alg}}, rp.Keys); err == nil {
			t.Errorf("allowlist with %s accepted", alg)
		}
	}
}

// JWKS behaviour under rotation, a flood of forged kids, and an IdP outage.
func TestJWKSRotationFloodOutage(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	ctx := context.Background()
	rp := newRP(t, idp, oidc.ValidatorConfig{})
	var mu sync.Mutex
	clock := time.Now()
	rp.Keys.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	v := rp.Validator()
	tok := func() string { return idp.Sign(idp.Claims("alice", "")) }

	first := tok()
	if _, err := v.Validate(ctx, first, ""); err != nil || idp.JWKSHits.Load() != 1 {
		t.Fatalf("first validate: %v hits=%d", err, idp.JWKSHits.Load())
	}

	// IdP rotates mid-session: unknown kid -> one refetch -> accepted; old key still published.
	idp.Rotate(true)
	advance(rp.Keys.MinRefetch)
	rotated := tok()
	if _, err := v.Validate(ctx, rotated, ""); err != nil || idp.JWKSHits.Load() != 2 {
		t.Fatalf("rotated key: %v hits=%d", err, idp.JWKSHits.Load())
	}
	if _, err := v.Validate(ctx, first, ""); err != nil {
		t.Fatalf("old key during overlap: %v", err)
	}

	// 1000 concurrent tokens with random kids cost the IdP at most one fetch per MinRefetch.
	advance(rp.Keys.MinRefetch)
	bogus := must(rsa.GenerateKey(rand.Reader, 2048))
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for range 1000 {
		wg.Go(func() {
			tk := jwt.NewWithClaims(jwt.SigningMethodRS256, idp.Claims("mallory", ""))
			tk.Header["kid"] = rand.Text()
			if _, err := v.Validate(ctx, must(tk.SignedString(bogus)), ""); err == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 0 || idp.JWKSHits.Load() != 3 {
		t.Fatalf("kid flood: accepted=%d hits=%d (want 3)", accepted.Load(), idp.JWKSHits.Load())
	}

	// IdP JWKS down and our cache past MaxAge: known keys keep working.
	idp.JWKSDown.Store(true)
	advance(rp.Keys.MaxAge + time.Second)
	if _, err := v.Validate(ctx, rotated, ""); err != nil {
		t.Fatalf("stale key while IdP down: %v", err)
	}
	// ...but a key we have never seen fails closed.
	idp.Rotate(false)
	advance(rp.Keys.MinRefetch)
	fresh := tok()
	if _, err := v.Validate(ctx, fresh, ""); err == nil {
		t.Fatal("unseen key accepted while JWKS unreachable")
	}

	// Back up: the new key verifies, and keys the IdP dropped stop verifying.
	idp.JWKSDown.Store(false)
	advance(rp.Keys.MinRefetch)
	if _, err := v.Validate(ctx, fresh, ""); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if _, err := v.Validate(ctx, first, ""); err == nil {
		t.Fatal("key removed from JWKS still accepted")
	}
}

// id_token validation with a warm JWKS cache: RS256 verify + claim checks.
func BenchmarkValidateIDToken(b *testing.B) {
	idp := oidctest.New()
	defer idp.Close()
	rp := newRP(b, idp, oidc.ValidatorConfig{})
	tok := idp.Sign(idp.Claims("alice", "n"))
	v := rp.Validator()
	if _, err := v.Validate(context.Background(), tok, "n"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := v.Validate(context.Background(), tok, "n"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
