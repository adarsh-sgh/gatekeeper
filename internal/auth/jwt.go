// Package auth validates OAuth2 bearer tokens (RS256 JWTs) against an
// issuer's JWKS and exposes the claims to handlers via context.
package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/adarsh-sgh/gatekeeper/internal/jwks"
)

const (
	ScopeCheck       = "policy:check"
	ScopePolicyWrite = "policy:write"
	ScopeAuditRead   = "audit:read"
	// ScopeTenantAdmin manages the tenant registry and acts on any tenant's
	// policies via the request's `tenant` field.
	ScopeTenantAdmin = "tenants:admin"
)

type Claims struct {
	jwt.RegisteredClaims
	Tenant string   `json:"tenant"`
	Roles  []string `json:"roles,omitempty"`
	Scope  string   `json:"scope,omitempty"` // space-separated, per RFC 8693
	SID    string   `json:"sid,omitempty"`   // session/refresh family; revoking it kills every token in it

	// Identity carried by front-door session tokens; empty for service tokens.
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Source string   `json:"src,omitempty"`
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

// Verifier checks signature, issuer, audience, expiry, the presence of a
// tenant claim and, if Revoked is set, the token's jti and sid. Keys come
// from a jwks.Set (kid cache, throttled refetch, stale-on-error).
//
// Verified tokens are remembered for CacheTTL (bounded by their exp): RS256
// verification is the single most expensive step per request, and service
// callers reuse one token for thousands of calls. Revocation is checked on
// every call, cached or not.
type Verifier struct {
	issuer, audience string
	keys             *jwks.Set
	CacheTTL         time.Duration
	Revoked          *RevocationList

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
	return &Verifier{issuer: issuer, audience: audience, keys: jwks.New(jwksURL), CacheTTL: time.Minute, cache: map[[32]byte]cached{}}
}

var ErrRevoked = errors.New("token revoked")

func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	c, err := v.verifyCached(ctx, token)
	if err != nil {
		return nil, err
	}
	if v.Revoked != nil && v.Revoked.Revoked(c.ID, c.SID) {
		return nil, ErrRevoked
	}
	return c, nil
}

func (v *Verifier) verifyCached(ctx context.Context, token string) (*Claims, error) {
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
	_, err := jwt.ParseWithClaims(token, claims, v.keys.Keyfunc(ctx),
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

// Bearer extracts the token from an Authorization header value.
func Bearer(header string) (string, bool) {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	return tok, ok && tok != ""
}
