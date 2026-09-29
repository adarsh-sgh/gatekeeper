package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/adarsh-sgh/gatekeeper/internal/jwks"
)

// Provider is the subset of the discovery document we use.
type Provider struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

// Discover fetches {issuer}/.well-known/openid-configuration. The document's
// issuer must equal the configured one exactly (OIDC Discovery 4.3), which
// stops a compromised or mixed-up provider from vouching for another.
func Discover(ctx context.Context, client *http.Client, issuer string) (*Provider, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: status %d", resp.StatusCode)
	}
	var p Provider
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&p); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	switch {
	case p.Issuer != issuer:
		return nil, fmt.Errorf("discovery: issuer %q != configured %q", p.Issuer, issuer)
	case p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.JWKSURI == "":
		return nil, errors.New("discovery: missing authorization, token or jwks endpoint")
	case !supportsS256(p.CodeChallengeMethods):
		return nil, errors.New("discovery: provider does not support PKCE S256")
	}
	return &p, nil
}

type Config struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
	Scopes                                      []string // "openid" is always sent
	HTTPClient                                  *http.Client
	Validator                                   ValidatorConfig // Issuer/ClientID filled in
}

// RP runs the authorization-code flow. Pending logins live server-side,
// keyed by state, and are single-use: a replayed callback finds nothing.
type RP struct {
	cfg  Config
	prov *Provider
	Keys *jwks.Set
	val  *Validator

	mu      sync.Mutex
	pending map[string]pending
}

type pending struct {
	verifier, nonce, returnTo string
	expires                   time.Time
}

const (
	pendingTTL = 10 * time.Minute
	pendingMax = 10000
)

func New(ctx context.Context, cfg Config) (*RP, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	prov, err := Discover(ctx, cfg.HTTPClient, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	keys := jwks.New(prov.JWKSURI)
	keys.Client = cfg.HTTPClient
	vc := cfg.Validator
	vc.Issuer, vc.ClientID = cfg.Issuer, cfg.ClientID
	val, err := NewValidator(vc, keys)
	if err != nil {
		return nil, err
	}
	return &RP{cfg: cfg, prov: prov, Keys: keys, val: val, pending: map[string]pending{}}, nil
}

func (rp *RP) Validator() *Validator { return rp.val }

func random(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Challenge is the PKCE S256 code_challenge for a verifier (RFC 7636 4.2).
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthCodeURL starts a login: fresh state, nonce and PKCE verifier (43
// chars), remembered until the callback. The caller should bind state to the
// browser (cookie) so a callback can't be completed in someone else's browser.
func (rp *RP) AuthCodeURL(returnTo string) (authURL, state string) {
	state, p := random(32), pending{verifier: random(32), nonce: random(32), returnTo: returnTo, expires: time.Now().Add(pendingTTL)}
	rp.mu.Lock()
	if len(rp.pending) >= pendingMax {
		rp.sweepLocked()
	}
	rp.pending[state] = p
	rp.mu.Unlock()
	q := url.Values{
		"response_type": {"code"}, "client_id": {rp.cfg.ClientID}, "redirect_uri": {rp.cfg.RedirectURL},
		"scope": {strings.Join(append([]string{"openid"}, rp.cfg.Scopes...), " ")},
		"state": {state}, "nonce": {p.nonce}, "code_challenge": {Challenge(p.verifier)}, "code_challenge_method": {"S256"},
	}
	return rp.prov.AuthorizationEndpoint + "?" + q.Encode(), state
}

func (rp *RP) sweepLocked() {
	now := time.Now()
	for s, p := range rp.pending {
		if now.After(p.expires) {
			delete(rp.pending, s)
		}
	}
	if len(rp.pending) >= pendingMax {
		clear(rp.pending) // under a flood, drop everything rather than grow
	}
}

var ErrState = errors.New("unknown, expired or already used state")

type Result struct {
	IDToken                  *IDToken
	AccessToken, RawIDToken  string
	RefreshToken, ReturnTo string
}

// Exchange redeems the code with the PKCE verifier and validates the id_token
// against the nonce sent in AuthCodeURL.
func (rp *RP) Exchange(ctx context.Context, state, code string) (*Result, error) {
	rp.mu.Lock()
	p, ok := rp.pending[state]
	delete(rp.pending, state)
	rp.mu.Unlock()
	if !ok || time.Now().After(p.expires) {
		return nil, ErrState
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rp.cfg.RedirectURL}, "code_verifier": {p.verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rp.prov.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(rp.cfg.ClientID), url.QueryEscape(rp.cfg.ClientSecret)) // RFC 6749 2.3.1
	resp, err := rp.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("token endpoint: status %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.IDToken == "" {
		return nil, fmt.Errorf("token endpoint: status %d error %q", resp.StatusCode, tr.Error)
	}
	idt, err := rp.val.Validate(ctx, tr.IDToken, p.nonce)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	return &Result{IDToken: idt, AccessToken: tr.AccessToken, RawIDToken: tr.IDToken, RefreshToken: tr.RefreshToken, ReturnTo: p.returnTo}, nil
}
