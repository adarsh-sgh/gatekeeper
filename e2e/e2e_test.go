//go:build e2e

// Package e2e drives the docker-compose stacks in deploy/ from the outside.
package e2e

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// waitHTTP polls url until it answers at all (any status) or the deadline passes.
func waitHTTP(t *testing.T, url string, d time.Duration) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			return
		}
	}
	t.Fatalf("%s not up after %s", url, d)
}

type resp struct {
	code int
	hdr  http.Header
	body string
}

func do(t *testing.T, method, url, token, body string, hdr ...string) resp {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r.StatusCode, r.Header, string(b)}
}

// devToken mints a token from gatekeeper's -dev-issuer.
func devToken(t *testing.T, gk, query string) string {
	t.Helper()
	r := do(t, "GET", gk+"/dev/token?"+query, "", "")
	if r.code != 200 {
		t.Fatalf("dev token: %d %s", r.code, r.body)
	}
	return r.body
}
