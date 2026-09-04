// Command gatekeeper runs the policy decision service.
//
//	gatekeeper -dev-issuer                   # in-memory store, embedded JWT issuer
//	gatekeeper -pg-dsn postgres://... \
//	  -issuer https://idp.example -jwks-url https://idp.example/.well-known/jwks.json
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/server"
	"github.com/adarsh-sgh/gatekeeper/internal/store"
	"github.com/adarsh-sgh/gatekeeper/internal/tlsutil"
)

func main() {
	var (
		grpcAddr  = flag.String("grpc", ":9090", "gRPC listen address")
		httpAddr  = flag.String("http", ":8080", "HTTP listen address (JSON API, /metrics, /healthz)")
		pgDSN     = flag.String("pg-dsn", os.Getenv("PG_DSN"), "Postgres DSN; empty = in-memory store")
		issuer    = flag.String("issuer", "", "expected JWT iss")
		audience  = flag.String("audience", "gatekeeper", "expected JWT aud")
		jwksURL   = flag.String("jwks-url", "", "JWKS endpoint of the issuer")
		devIssuer = flag.Bool("dev-issuer", false, "embed a token issuer and print an admin token for tenant 'acme'")
		tlsCert   = flag.String("tls-cert", "", "gRPC server certificate (PEM); enables TLS")
		tlsKey    = flag.String("tls-key", "", "gRPC server key (PEM)")
		clientCA  = flag.String("tls-client-ca", "", "CA bundle for client certs; enables mTLS on gRPC")
	)
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*grpcAddr, *httpAddr, *pgDSN, *issuer, *audience, *jwksURL, *devIssuer, *tlsCert, *tlsKey, *clientCA, log); err != nil {
		log.Error("exit", "err", err)
		os.Exit(1)
	}
}

func run(grpcAddr, httpAddr, pgDSN, issuer, audience, jwksURL string, devIssuer bool, tlsCert, tlsKey, clientCA string, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var st store.Store = store.NewMemory()
	if pgDSN != "" {
		pg, err := store.NewPostgres(ctx, pgDSN)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		st = pg
	}
	defer st.Close()

	extra := map[string]http.Handler{}
	if devIssuer {
		iss, err := auth.NewIssuer("gatekeeper-dev", audience)
		if err != nil {
			return err
		}
		host, port, err := net.SplitHostPort(httpAddr)
		if err != nil {
			return fmt.Errorf("-http %q: %w", httpAddr, err)
		}
		if host == "" {
			host = "127.0.0.1"
		}
		issuer, jwksURL = iss.Name, "http://"+net.JoinHostPort(host, port)+"/dev/jwks.json"
		extra["GET /dev/jwks.json"] = http.HandlerFunc(iss.JWKS)
		tok := iss.Mint("dev-admin", "acme", []string{"admin"},
			auth.ScopeCheck+" "+auth.ScopePolicyWrite+" "+auth.ScopeAuditRead, 12*time.Hour)
		fmt.Printf("export TOKEN=%s\n", tok)
	}
	if issuer == "" || jwksURL == "" {
		return fmt.Errorf("-issuer and -jwks-url are required (or use -dev-issuer)")
	}
	verifier := auth.NewVerifier(issuer, audience, jwksURL)
	svc := server.New(st, log)

	opts := []grpc.ServerOption{grpc.UnaryInterceptor(server.UnaryAuth(verifier))}
	if tlsCert != "" {
		cfg, err := tlsutil.ServerConfig(tlsCert, tlsKey, clientCA)
		if err != nil {
			return err
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(cfg)))
	}
	gs := grpc.NewServer(opts...)
	pb.RegisterGatekeeperServer(gs, svc)
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return err
	}
	hs := &http.Server{Addr: httpAddr, Handler: server.NewHTTPHandler(svc, verifier, extra), ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	go func() { errc <- gs.Serve(lis) }()
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("listening", "grpc", grpcAddr, "http", httpAddr, "mtls", clientCA != "", "store", map[bool]string{true: "postgres", false: "memory"}[pgDSN != ""])

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gs.GracefulStop()
	return hs.Shutdown(shutdownCtx)
}
