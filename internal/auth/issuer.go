package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/adarsh-sgh/gatekeeper/internal/jwks"
)

// Issuer is a minimal OAuth2-style token issuer: RSA keys, a JWKS endpoint,
// and Mint. Used by tests, by `-dev-issuer`, and by the front door for its
// own session tokens.
//
// Rotation is two-phase: PrepareNext publishes the next key without signing
// with it, so verifiers refreshing on their own schedule already hold it when
// Rotate switches over; the old key stays published until tokens it signed
// have expired.
type Issuer struct {
	Name     string
	Audience string

	mu   sync.RWMutex
	cur  signingKey
	next *signingKey
	old  []signingKey
}

type signingKey struct {
	kid      string
	key      *rsa.PrivateKey
	retireAt time.Time // zero while current or next
}

func newKey() (signingKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return signingKey{}, err
	}
	return signingKey{kid: jwks.Thumbprint(&key.PublicKey), key: key}, nil
}

func NewIssuer(name, audience string) (*Issuer, error) {
	k, err := newKey()
	if err != nil {
		return nil, err
	}
	return &Issuer{Name: name, Audience: audience, cur: k}, nil
}

// PrepareNext publishes a new key in the JWKS without signing with it yet.
func (i *Issuer) PrepareNext() error {
	k, err := newKey()
	if err != nil {
		return err
	}
	i.mu.Lock()
	i.next = &k
	i.mu.Unlock()
	return nil
}

// Rotate signs with the prepared key from now on (a fresh one if none was
// prepared) and keeps publishing the old one for maxTokenTTL.
func (i *Issuer) Rotate(maxTokenTTL time.Duration) error {
	i.mu.RLock()
	prepared := i.next != nil
	i.mu.RUnlock()
	if !prepared {
		if err := i.PrepareNext(); err != nil {
			return err
		}
	}
	now := time.Now()
	i.mu.Lock()
	defer i.mu.Unlock()
	old := i.cur
	old.retireAt = now.Add(maxTokenTTL)
	i.cur, i.next = *i.next, nil
	kept := i.old[:0]
	for _, k := range i.old {
		if now.Before(k.retireAt) {
			kept = append(kept, k)
		}
	}
	i.old = append(kept, old)
	return nil
}

// Kid is the current signing key's id.
func (i *Issuer) Kid() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cur.kid
}

func (i *Issuer) Mint(sub, tenant string, roles []string, scope string, ttl time.Duration) string {
	return i.MintClaims(Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: sub}, Tenant: tenant, Roles: roles, Scope: scope}, ttl)
}

// MintClaims fills iss, aud, iat, exp and a random jti, then signs.
func (i *Issuer) MintClaims(c Claims, ttl time.Duration) string {
	now := time.Now()
	c.Issuer, c.Audience = i.Name, []string{i.Audience}
	c.IssuedAt, c.ExpiresAt = jwt.NewNumericDate(now), jwt.NewNumericDate(now.Add(ttl))
	if c.ID == "" {
		c.ID = RandomID()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	i.mu.RLock()
	k := i.cur
	i.mu.RUnlock()
	tok.Header["kid"] = k.kid
	s, err := tok.SignedString(k.key)
	if err != nil {
		panic(err) // RSA signing with a valid key cannot fail
	}
	return s
}

// JWKS serves current, next and not-yet-retired keys in RFC 7517 format.
func (i *Issuer) JWKS(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	i.mu.RLock()
	keys := []map[string]string{jwks.PublicJWK(&i.cur.key.PublicKey)}
	if i.next != nil {
		keys = append(keys, jwks.PublicJWK(&i.next.key.PublicKey))
	}
	for _, k := range i.old {
		if now.Before(k.retireAt) {
			keys = append(keys, jwks.PublicJWK(&k.key.PublicKey))
		}
	}
	i.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

// RandomID is 128 random bits, hex.
func RandomID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
