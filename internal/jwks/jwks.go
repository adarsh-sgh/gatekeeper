// Package jwks caches an issuer's signing keys (RFC 7517) by kid.
//
// An unknown kid triggers a refetch at most once per MinRefetch, so a flood
// of forged kids costs the IdP one request per interval, not one per token.
// A failed fetch keeps serving the last good keys: an IdP outage must not
// log everyone out. Keys older than MaxAge are refreshed on the next lookup,
// which is how verifiers pick up a "next" key published ahead of rotation.
package jwks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Key struct {
	Kid    string
	Alg    string // from the JWK; "" = any alg matching the key type
	Public crypto.PublicKey
}

type Set struct {
	url        string
	Client     *http.Client
	MinRefetch time.Duration
	MaxAge     time.Duration
	Now        func() time.Time

	mu      sync.RWMutex
	keys    map[string]Key
	fetched time.Time // last successful fetch

	fetchMu sync.Mutex // one fetch at a time; lookups for known kids never wait on it
	tried   time.Time  // last attempt, success or not
	fetches atomic.Int64
}

func New(url string) *Set {
	return &Set{url: url, Client: &http.Client{Timeout: 5 * time.Second},
		MinRefetch: 10 * time.Second, MaxAge: 10 * time.Minute, Now: time.Now, keys: map[string]Key{}}
}

// Fetches counts HTTP fetches attempted (tests, metrics).
func (s *Set) Fetches() int64 { return s.fetches.Load() }

var ErrUnknownKid = errors.New("unknown kid")

// Lookup returns the key for kid, fetching the JWKS when the kid is unknown
// or the cache is older than MaxAge, subject to MinRefetch.
func (s *Set) Lookup(ctx context.Context, kid string) (Key, error) {
	s.mu.RLock()
	k, ok := s.keys[kid]
	stale := s.Now().Sub(s.fetched) > s.MaxAge
	s.mu.RUnlock()
	if ok && !stale {
		return k, nil
	}
	err := s.refresh(ctx)
	s.mu.RLock()
	k2, ok2 := s.keys[kid]
	s.mu.RUnlock()
	switch {
	case ok2:
		return k2, nil
	case ok && err != nil:
		return k, nil // IdP down: serve the cached key
	case err != nil:
		return Key{}, fmt.Errorf("%w %q: %v", ErrUnknownKid, kid, err)
	}
	return Key{}, fmt.Errorf("%w %q", ErrUnknownKid, kid)
}

var errThrottled = errors.New("refetch throttled")

func (s *Set) refresh(ctx context.Context) error {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	now := s.Now()
	if now.Sub(s.tried) < s.MinRefetch {
		return errThrottled // waiters behind a fetch that just ran land here too
	}
	s.tried = now
	s.fetches.Add(1)
	keys, err := s.fetch(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.keys, s.fetched = keys, now // replace: keys the IdP dropped stop verifying
	s.mu.Unlock()
	return nil
}

type jwk struct {
	Kty, Kid, Alg, Use, N, E, Crv, X, Y string
}

func (s *Set) fetch(ctx context.Context) (map[string]Key, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	var doc struct{ Keys []jwk }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	keys := map[string]Key{}
	for _, j := range doc.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		pub, err := j.public()
		if err != nil {
			continue // one bad key must not hide the others
		}
		keys[j.Kid] = Key{Kid: j.Kid, Alg: j.Alg, Public: pub}
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks has no usable signing keys")
	}
	return keys, nil
}

func b64int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("bad base64url integer")
	}
	return new(big.Int).SetBytes(b), nil
}

func (j jwk) public() (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err1 := b64int(j.N)
		e, err2 := b64int(j.E)
		if err := errors.Join(err1, err2); err != nil {
			return nil, err
		}
		if n.BitLen() < 2048 || !e.IsInt64() || e.Int64() < 3 {
			return nil, errors.New("weak RSA key")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var c elliptic.Curve
		switch j.Crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		default:
			return nil, fmt.Errorf("curve %q", j.Crv)
		}
		x, err1 := b64int(j.X)
		y, err2 := b64int(j.Y)
		if err := errors.Join(err1, err2); err != nil {
			return nil, err
		}
		if !c.IsOnCurve(x, y) { //nolint:staticcheck // point validation is the point
			return nil, errors.New("EC point not on curve")
		}
		return &ecdsa.PublicKey{Curve: c, X: x, Y: y}, nil
	}
	return nil, fmt.Errorf("kty %q", j.Kty)
}

// Keyfunc resolves the token's kid and binds alg to key type: an RSA key
// only verifies RS*/PS*, an EC key only ES*, and a JWK that pins "alg" only
// that alg. HS* never matches, so a public key can't be used as an HMAC secret.
func (s *Set) Keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		k, err := s.Lookup(ctx, kid)
		if err != nil {
			return nil, err
		}
		alg := t.Method.Alg()
		if k.Alg != "" && k.Alg != alg {
			return nil, fmt.Errorf("alg %s does not match key %q (%s)", alg, kid, k.Alg)
		}
		switch k.Public.(type) {
		case *rsa.PublicKey:
			if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
				return k.Public, nil
			}
		case *ecdsa.PublicKey:
			if strings.HasPrefix(alg, "ES") {
				return k.Public, nil
			}
		}
		return nil, fmt.Errorf("alg %s not allowed for key %q", alg, kid)
	}
}

// PublicJWK encodes an RSA public key with its RFC 7638 thumbprint as kid.
func PublicJWK(pub *rsa.PublicKey) map[string]string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return map[string]string{"kty": "RSA", "kid": Thumbprint(pub), "use": "sig", "alg": "RS256", "n": n, "e": e}
}

// Thumbprint is the RFC 7638 SHA-256 JWK thumbprint, base64url.
func Thumbprint(pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	sum := sha256.Sum256(fmt.Appendf(nil, `{"e":"%s","kty":"RSA","n":"%s"}`, e, n))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
