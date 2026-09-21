// Package auth validates OAuth2 bearer tokens (RS256 JWTs) against an
// issuer's JWKS and exposes the claims to handlers via context.
package auth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ScopeCheck       = "policy:check"
	ScopePolicyWrite = "policy:write"
	ScopeAuditRead   = "audit:read"
)

type Claims struct {
	jwt.RegisteredClaims
	Tenant string   `json:"tenant"`
	Roles  []string `json:"roles,omitempty"`
	Scope  string   `json:"scope,omitempty"` // space-separated, per RFC 8693
}

func (c *Claims) HasScope(s string) bool { return slices.Contains(strings.Fields(c.Scope), s) }

type ctxKey struct{}

func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// Verifier checks signature, issuer, audience, expiry and the presence of a
// tenant claim. Keys are fetched lazily from jwksURL and refreshed at most
// once a minute when an unknown kid shows up (key rotation).
//
// Verified tokens are remembered for CacheTTL (bounded by their exp): RS256
// verification is the single most expensive step per request, and service
// callers reuse one token for thousands of calls.
type Verifier struct {
	issuer, audience, jwksURL string
	client                    *http.Client
	CacheTTL                  time.Duration

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time

	cmu   sync.RWMutex
	cache map[[32]byte]cached
}

type cached struct {
	claims *Claims
	until  time.Time
}

// cacheMax bounds memory; on overflow the whole cache is dropped, which only
// costs one extra signature check per live token.
const cacheMax = 10000

func NewVerifier(issuer, audience, jwksURL string) *Verifier {
	return &Verifier{issuer: issuer, audience: audience, jwksURL: jwksURL, CacheTTL: time.Minute,
		client: &http.Client{Timeout: 5 * time.Second}, keys: map[string]*rsa.PublicKey{}, cache: map[[32]byte]cached{}}
}

func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	if v.CacheTTL <= 0 {
		return v.verify(ctx, token)
	}
	key := sha256.Sum256([]byte(token))
	now := time.Now()
	v.cmu.RLock()
	c, ok := v.cache[key]
	v.cmu.RUnlock()
	if ok && now.Before(c.until) {
		return c.claims, nil
	}
	claims, err := v.verify(ctx, token)
	if err != nil {
		return nil, err
	}
	until := now.Add(v.CacheTTL)
	if exp := claims.ExpiresAt.Time; exp.Before(until) {
		until = exp
	}
	v.cmu.Lock()
	if len(v.cache) >= cacheMax {
		clear(v.cache)
	}
	v.cache[key] = cached{claims: claims, until: until}
	v.cmu.Unlock()
	return claims, nil
}

func (v *Verifier) verify(ctx context.Context, token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, v.keyFor,
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.issuer), jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil {
		return nil, err
	}
	if claims.Tenant == "" || claims.Subject == "" {
		return nil, errors.New("token missing tenant or sub claim")
	}
	return claims, nil
}

func (v *Verifier) keyFor(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if time.Since(v.lastFetch) < time.Minute {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	if err := v.refreshLocked(); err != nil {
		return nil, err
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

type jwk struct {
	Kty, Kid, N, E string
}

func (v *Verifier) refreshLocked() error {
	v.lastFetch = time.Now()
	resp, err := v.client.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	var doc struct{ Keys []jwk }
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err := errors.Join(err1, err2); err != nil {
			return fmt.Errorf("jwk %q: %w", k.Kid, err)
		}
		v.keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return nil
}

// Bearer extracts the token from an Authorization header value.
func Bearer(header string) (string, bool) {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	return tok, ok && tok != ""
}
