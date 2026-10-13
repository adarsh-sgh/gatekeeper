// Command gatekeeper runs the policy decision service.
//
//	gatekeeper -dev-issuer                   # in-memory store, embedded JWT issuer
//	gatekeeper -pg-dsn postgres://... \
//	  -issuer https://idp.example -jwks-url https://idp.example/.well-known/jwks.json
package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/ratelimit"
	"github.com/adarsh-sgh/gatekeeper/internal/server"
	"github.com/adarsh-sgh/gatekeeper/internal/store"
	"github.com/adarsh-sgh/gatekeeper/internal/tlsutil"
)

type config struct {
	grpcAddr, httpAddr         string
	pgDSN                      string
	issuer, audience, jwksURL  string
	devIssuer, pprof, outbox   bool
	devRotate, tokenCache      time.Duration
	tlsCert, tlsKey, clientCA  string
	rate                       float64
	burst                      int
	drainDelay, shutdownWindow time.Duration
	// started, if set, receives the bound addresses once both listeners are up (tests).
	started chan<- [2]string
}

func main() {
	var c config
	flag.StringVar(&c.grpcAddr, "grpc", ":9090", "gRPC listen address")
	flag.StringVar(&c.httpAddr, "http", ":8080", "HTTP listen address (JSON API, /metrics, /healthz, /readyz)")
	flag.StringVar(&c.pgDSN, "pg-dsn", os.Getenv("PG_DSN"), "Postgres DSN; empty = in-memory store")
	flag.BoolVar(&c.outbox, "outbox", false, "with -pg-dsn: write each audit event to audit_outbox in the same statement, for gkrelay")
	flag.StringVar(&c.issuer, "issuer", "", "expected JWT iss")
	flag.StringVar(&c.audience, "audience", "gatekeeper", "expected JWT aud")
	flag.StringVar(&c.jwksURL, "jwks-url", "", "JWKS endpoint of the issuer")
	flag.BoolVar(&c.devIssuer, "dev-issuer", false, "embed a token issuer and print an admin token for tenant 'acme'")
	flag.DurationVar(&c.devRotate, "dev-key-rotate", 0, "with -dev-issuer: rotate the signing key this often; the next key is published one period ahead")
	flag.StringVar(&c.tlsCert, "tls-cert", "", "gRPC server certificate (PEM); enables TLS")
	flag.StringVar(&c.tlsKey, "tls-key", "", "gRPC server key (PEM)")
	flag.StringVar(&c.clientCA, "tls-client-ca", "", "CA bundle for client certs; enables mTLS on gRPC")
	flag.DurationVar(&c.tokenCache, "token-cache", time.Minute, "cache verified tokens this long (capped at expiry); 0 verifies RS256 on every request")
	flag.BoolVar(&c.pprof, "pprof", false, "serve net/http/pprof under /debug/pprof/ on the HTTP port")
	flag.Float64Var(&c.rate, "rate", 0, "per-tenant requests/second; 0 disables rate limiting")
	flag.IntVar(&c.burst, "burst", 100, "per-tenant burst allowance when -rate is set")
	flag.DurationVar(&c.drainDelay, "drain", 5*time.Second, "on SIGTERM: time to fail readiness before closing listeners")
	flag.DurationVar(&c.shutdownWindow, "shutdown-timeout", 10*time.Second, "after drain: time for in-flight requests to finish")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(c, log); err != nil {
		log.Error("exit", "err", err)
		os.Exit(1)
	}
}

func run(c config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var st store.Store = store.NewMemory()
	if c.pgDSN != "" {
		var opts []store.Option
		if c.outbox {
			opts = append(opts, store.WithOutbox())
		}
		pg, err := store.NewPostgres(ctx, c.pgDSN, opts...)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		st = pg
	}
	defer st.Close()

	extra := map[string]http.Handler{}
	if c.devIssuer {
		iss, err := auth.NewIssuer("gatekeeper-dev", c.audience)
		if err != nil {
			return err
		}
		host, port, err := net.SplitHostPort(c.httpAddr)
		if err != nil {
			return fmt.Errorf("-http %q: %w", c.httpAddr, err)
		}
		if host == "" {
			host = "127.0.0.1"
		}
		c.issuer, c.jwksURL = iss.Name, "http://"+net.JoinHostPort(host, port)+"/dev/jwks.json"
		extra["GET /dev/jwks.json"] = http.HandlerFunc(iss.JWKS)
		// Load tests and e2e: ?tenant=t[&sub=u&roles=a,b&scope=...]; one token per tenant/user.
		extra["GET /dev/token"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			sub, scope := cmp.Or(q.Get("sub"), "dev-admin"), cmp.Or(q.Get("scope"), auth.ScopeCheck+" "+auth.ScopePolicyWrite)
			var roles []string
			if q.Get("roles") != "" {
				roles = strings.Split(q.Get("roles"), ",")
			}
			w.Write([]byte(iss.Mint(sub, q.Get("tenant"), roles, scope, time.Hour)))
		})
		tok := iss.Mint("dev-admin", "acme", []string{"admin"},
			auth.ScopeCheck+" "+auth.ScopePolicyWrite+" "+auth.ScopeAuditRead+" "+auth.ScopeTenantAdmin, 12*time.Hour)
		fmt.Printf("export TOKEN=%s\n", tok)
		if c.devRotate > 0 {
			if err := iss.PrepareNext(); err != nil {
				return err
			}
			go rotateEvery(ctx, iss, c.devRotate, log)
		}
	}
	if c.pprof {
		extra["GET /debug/pprof/"] = http.HandlerFunc(pprof.Index)
		extra["GET /debug/pprof/profile"] = http.HandlerFunc(pprof.Profile)
		extra["GET /debug/pprof/{name}"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pprof.Handler(r.PathValue("name")).ServeHTTP(w, r)
		})
	}
	if c.issuer == "" || c.jwksURL == "" {
		return fmt.Errorf("-issuer and -jwks-url are required (or use -dev-issuer)")
	}
	health := server.NewHealth(st)
	v := auth.NewVerifier(c.issuer, c.audience, c.jwksURL)
	v.CacheTTL = c.tokenCache
	opts := server.Options{Verifier: v, Health: health, Log: log, Extra: extra}
	if c.rate > 0 {
		opts.Limiter = ratelimit.New(c.rate, c.burst)
		go opts.Limiter.SweepEvery(time.Minute, 10*time.Minute, ctx.Done())
	}
	svc := server.New(st, log)

	gopts := []grpc.ServerOption{server.GRPCInterceptors(opts)}
	if c.tlsCert != "" {
		cfg, err := tlsutil.ServerConfig(c.tlsCert, c.tlsKey, c.clientCA)
		if err != nil {
			return err
		}
		gopts = append(gopts, grpc.Creds(credentials.NewTLS(cfg)))
	}
	gs := grpc.NewServer(gopts...)
	pb.RegisterGatekeeperServer(gs, svc)
	authv3.RegisterAuthorizationServer(gs, server.NewExtAuthz(svc, opts))
	health.Register(gs)
	glis, err := net.Listen("tcp", c.grpcAddr)
	if err != nil {
		return err
	}
	hlis, err := net.Listen("tcp", c.httpAddr)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: server.NewHTTPHandler(svc, opts), ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	go func() { errc <- gs.Serve(glis) }()
	go func() { errc <- hs.Serve(hlis) }()
	log.Info("listening", "grpc", glis.Addr().String(), "http", hlis.Addr().String(), "mtls", c.clientCA != "",
		"store", map[bool]string{true: "postgres", false: "memory"}[c.pgDSN != ""], "outbox", c.outbox, "rate", c.rate)
	if c.started != nil {
		c.started <- [2]string{glis.Addr().String(), hlis.Addr().String()}
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// Drain: fail readiness first so upstreams stop routing to us, keep
	// serving meanwhile, then close listeners and let in-flight work finish.
	log.Info("draining", "delay", c.drainDelay, "shutdown_timeout", c.shutdownWindow)
	health.Drain()
	time.Sleep(c.drainDelay)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), c.shutdownWindow)
	defer cancel()
	stopped := make(chan struct{})
	go func() { gs.GracefulStop(); close(stopped) }()
	err = hs.Shutdown(shutdownCtx)
	select {
	case <-stopped:
	case <-shutdownCtx.Done():
		gs.Stop()
		log.Warn("shutdown timeout: killed in-flight gRPC requests")
	}
	log.Info("stopped")
	return err
}

// rotateEvery switches to the pre-published key and publishes the next one.
// Old keys stay in the JWKS for 12h, the longest dev token TTL.
func rotateEvery(ctx context.Context, iss *auth.Issuer, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := iss.Rotate(12 * time.Hour)
		if err == nil {
			err = iss.PrepareNext()
		}
		log.Info("dev issuer key rotated", "kid", iss.Kid(), "err", err)
	}
}
