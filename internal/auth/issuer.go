package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Issuer is a minimal OAuth2-style token issuer: one RSA key, a JWKS
// endpoint, and Mint. Used by tests and by `-dev-issuer` for local runs.
type Issuer struct {
	Name     string
	Audience string
	key      *rsa.PrivateKey
	kid      string
}

func NewIssuer(name, audience string) (*Issuer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Issuer{Name: name, Audience: audience, key: key, kid: "k-" + time.Now().Format("20060102150405")}, nil
}

func (i *Issuer) Mint(sub, tenant string, roles []string, scope string, ttl time.Duration) string {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: i.Name, Subject: sub, Audience: []string{i.Audience},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttl))},
		Tenant: tenant, Roles: roles, Scope: scope,
	})
	tok.Header["kid"] = i.kid
	s, err := tok.SignedString(i.key)
	if err != nil {
		panic(err) // RSA signing with a valid key cannot fail
	}
	return s
}

// JWKS serves the public key in RFC 7517 format.
func (i *Issuer) JWKS(w http.ResponseWriter, _ *http.Request) {
	pub := i.key.PublicKey
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"keys": []jwk{{
		Kty: "RSA", Kid: i.kid,
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}
