// Package oidc is an OpenID Connect relying party: discovery, the
// authorization-code flow with PKCE (S256), state and nonce, and id_token
// validation against the provider's JWKS.
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/adarsh-sgh/gatekeeper/internal/jwks"
)

// IDToken is the validated id_token. Claims holds every claim for mapping.
type IDToken struct {
	jwt.RegisteredClaims
	Nonce  string         `json:"nonce"`
	AZP    string         `json:"azp"`
	SID    string         `json:"sid"`
	Claims map[string]any `json:"-"`
}

// Revoker is satisfied by auth.RevocationList.
type Revoker interface{ Revoked(ids ...string) bool }

type ValidatorConfig struct {
	Issuer, ClientID string
	Algs             []string      // default RS256, ES256; never "none" or HS*
	Leeway           time.Duration // clock skew allowed on exp/iat/nbf; default 30s
	Now              func() time.Time
	Revoked          Revoker
}

type Validator struct {
	cfg  ValidatorConfig
	keys *jwks.Set
}

func NewValidator(cfg ValidatorConfig, keys *jwks.Set) (*Validator, error) {
	if len(cfg.Algs) == 0 {
		cfg.Algs = []string{"RS256", "ES256"}
	}
	for _, a := range cfg.Algs {
		if a == "none" || strings.HasPrefix(a, "HS") {
			return nil, fmt.Errorf("alg %q not allowed: id_tokens are verified with the IdP's public keys", a)
		}
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Validator{cfg: cfg, keys: keys}, nil
}

var (
	ErrNonce   = errors.New("id_token nonce mismatch")
	ErrAZP     = errors.New("id_token azp does not match client_id")
	ErrRevoked = errors.New("id_token revoked")
)

// Validate checks signature (kid from JWKS, alg allowlisted and bound to
// the key type), iss, aud, azp, exp/iat/nbf with leeway, nonce and the
// revocation list, per OIDC Core 3.1.3.7.
func (v *Validator) Validate(ctx context.Context, raw, nonce string) (*IDToken, error) {
	tok := &IDToken{}
	_, err := jwt.ParseWithClaims(raw, tok, v.keys.Keyfunc(ctx),
		jwt.WithValidMethods(v.cfg.Algs), jwt.WithIssuer(v.cfg.Issuer), jwt.WithAudience(v.cfg.ClientID),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(v.cfg.Leeway), jwt.WithTimeFunc(v.cfg.Now))
	if err != nil {
		return nil, err
	}
	if tok.IssuedAt == nil || tok.Subject == "" {
		return nil, errors.New("id_token missing iat or sub")
	}
	// Multiple audiences require azp; a present azp must be us (OIDC Core 3.1.3.7 steps 4-5).
	if (len(tok.Audience) > 1 || tok.AZP != "") && tok.AZP != v.cfg.ClientID {
		return nil, ErrAZP
	}
	if nonce != "" && tok.Nonce != nonce {
		return nil, ErrNonce
	}
	if v.cfg.Revoked != nil && v.cfg.Revoked.Revoked(tok.ID, tok.SID) {
		return nil, ErrRevoked
	}
	// Signature verified above, so the payload segment is trusted.
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
	if err := json.Unmarshal(payload, &tok.Claims); err != nil {
		return nil, err
	}
	return tok, nil
}

// Strings reads a string or string-array claim (e.g. groups).
func (t *IDToken) Strings(name string) []string {
	switch v := t.Claims[name].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// String reads a string claim.
func (t *IDToken) String(name string) string {
	s, _ := t.Claims[name].(string)
	return s
}

func supportsS256(methods []string) bool {
	return len(methods) == 0 || slices.Contains(methods, "S256")
}
