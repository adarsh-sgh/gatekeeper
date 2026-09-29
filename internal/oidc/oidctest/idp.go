// Package oidctest is an in-process OpenID provider for tests: discovery,
// JWKS, an auto-approving authorize endpoint, and a token endpoint that
// enforces client auth, redirect_uri, single-use codes and PKCE S256.
// Tests can rotate its key, take its JWKS down, and mint arbitrary tokens.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/adarsh-sgh/gatekeeper/internal/jwks"
	"github.com/adarsh-sgh/gatekeeper/internal/oidc"
)

type IdP struct {
	Server                 *httptest.Server
	Issuer                 string
	ClientID, ClientSecret string

	JWKSDown atomic.Bool
	JWKSHits atomic.Int64

	mu    sync.Mutex
	keys  []*rsa.PrivateKey // [0] signs; all are published
	codes map[string]grant
	// User is the identity the next login returns (claims merged into the id_token).
	User jwt.MapClaims
	// NonceOverride, if set, replaces the nonce echoed in id_tokens (mix-up tests).
	NonceOverride string
}

type grant struct {
	redirect, challenge, nonce string
	user                       jwt.MapClaims
}

// New starts a TLS IdP; use Client() for requests to it.
func New() *IdP {
	i := &IdP{ClientID: "gatekeeper", ClientSecret: "s3cret", codes: map[string]grant{},
		User: jwt.MapClaims{"sub": "alice", "email": "alice@example.org", "groups": []string{"eng"}}}
	i.keys = []*rsa.PrivateKey{mustKey()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", i.discovery)
	mux.HandleFunc("GET /jwks", i.jwks)
	mux.HandleFunc("GET /authorize", i.authorize)
	mux.HandleFunc("POST /token", i.token)
	i.Server = httptest.NewTLSServer(mux)
	i.Issuer = i.Server.URL
	return i
}

func (i *IdP) Close()               { i.Server.Close() }
func (i *IdP) Client() *http.Client { return i.Server.Client() }

func mustKey() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

// Rotate signs with a new key from now on; keepOld leaves the old one published.
func (i *IdP) Rotate(keepOld bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	k := mustKey()
	if keepOld {
		i.keys = append([]*rsa.PrivateKey{k}, i.keys...)
	} else {
		i.keys = []*rsa.PrivateKey{k}
	}
}

func (i *IdP) Key() *rsa.PrivateKey {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.keys[0]
}

// Claims returns valid id_token claims for sub, to be tweaked by tests.
func (i *IdP) Claims(sub, nonce string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{"iss": i.Issuer, "aud": i.ClientID, "sub": sub, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": rand.Text()}
}

// Sign mints an RS256 token with the current key and its kid.
func (i *IdP) Sign(c jwt.MapClaims) string {
	k := i.Key()
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	t.Header["kid"] = jwks.Thumbprint(&k.PublicKey)
	s, _ := t.SignedString(k)
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (i *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"issuer": i.Issuer, "authorization_endpoint": i.Issuer + "/authorize",
		"token_endpoint": i.Issuer + "/token", "jwks_uri": i.Issuer + "/jwks", "code_challenge_methods_supported": []string{"S256"}})
}

func (i *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	i.JWKSHits.Add(1)
	if i.JWKSDown.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	i.mu.Lock()
	keys := make([]map[string]string, 0, len(i.keys))
	for _, k := range i.keys {
		keys = append(keys, jwks.PublicJWK(&k.PublicKey))
	}
	i.mu.Unlock()
	writeJSON(w, 200, map[string]any{"keys": keys})
}

func (i *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != i.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	code := rand.Text()
	i.mu.Lock()
	i.codes[code] = grant{redirect: q.Get("redirect_uri"), challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), user: i.User}
	i.mu.Unlock()
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
}

func (i *IdP) token(w http.ResponseWriter, r *http.Request) {
	id, secret, _ := r.BasicAuth()
	if id != i.ClientID || secret != i.ClientSecret {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	i.mu.Lock()
	g, ok := i.codes[r.FormValue("code")]
	delete(i.codes, r.FormValue("code")) // single use
	nonce := g.nonce
	if i.NonceOverride != "" {
		nonce = i.NonceOverride
	}
	i.mu.Unlock()
	if !ok || r.FormValue("grant_type") != "authorization_code" || r.FormValue("redirect_uri") != g.redirect ||
		oidc.Challenge(r.FormValue("code_verifier")) != g.challenge {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	c := i.Claims("", nonce)
	for k, v := range g.user {
		c[k] = v
	}
	writeJSON(w, 200, map[string]any{"access_token": rand.Text(), "token_type": "Bearer", "expires_in": 300, "id_token": i.Sign(c)})
}
