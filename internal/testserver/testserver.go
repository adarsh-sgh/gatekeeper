// Package testserver runs an in-memory gatekeeper on a real localhost port
// for tests of clients (gkctl, the Terraform provider) that dial by address.
package testserver

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/server"
	"github.com/adarsh-sgh/gatekeeper/internal/store"
)

type Server struct {
	Addr string
	Iss  *auth.Issuer
	// AdminToken carries every scope including tenants:admin.
	AdminToken string
}

func Start(t testing.TB) *Server {
	t.Helper()
	iss, err := auth.NewIssuer("https://issuer.test", "gatekeeper")
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(iss.JWKS))
	t.Cleanup(jwks.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	o := server.Options{Verifier: auth.NewVerifier(iss.Name, "gatekeeper", jwks.URL), Log: log}
	gs := grpc.NewServer(server.GRPCInterceptors(o))
	pb.RegisterGatekeeperServer(gs, server.New(store.NewMemory(), log))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	scopes := auth.ScopeCheck + " " + auth.ScopePolicyWrite + " " + auth.ScopeAuditRead + " " + auth.ScopeTenantAdmin
	return &Server{Addr: lis.Addr().String(), Iss: iss, AdminToken: iss.Mint("ops", "root", nil, scopes, time.Hour)}
}

// Token mints a token for tenant with the given space-separated scopes.
func (s *Server) Token(sub, tenant, scope string) string {
	return s.Iss.Mint(sub, tenant, nil, scope, time.Hour)
}
