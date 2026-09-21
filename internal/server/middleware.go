package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/metrics"
	"github.com/adarsh-sgh/gatekeeper/internal/ratelimit"
)

// RequestIDHeader is honoured on ingress (HTTP header or gRPC metadata) and
// always echoed back, so a caller can correlate its logs with ours.
const RequestIDHeader = "x-request-id"

// reqInfo travels with the request context so the access log, which wraps
// auth, can still report the tenant resolved further in.
type reqInfo struct {
	id     string
	tenant string
}

type reqKey struct{}

func withReqInfo(ctx context.Context, ri *reqInfo) context.Context {
	return context.WithValue(ctx, reqKey{}, ri)
}

func info(ctx context.Context) *reqInfo {
	ri, _ := ctx.Value(reqKey{}).(*reqInfo)
	return ri
}

// RequestID returns the id assigned to the request in ctx, or "".
func RequestID(ctx context.Context) string {
	if ri := info(ctx); ri != nil {
		return ri.id
	}
	return ""
}

func newRequestID(given string) string {
	if given != "" && len(given) <= 128 {
		return given
	}
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func setTenant(ctx context.Context, tenant string) {
	if ri := info(ctx); ri != nil {
		ri.tenant = tenant
	}
}

// Options wires the cross-cutting pieces into both transports.
type Options struct {
	Verifier *auth.Verifier
	Limiter  *ratelimit.Limiter // nil disables per-tenant rate limiting
	Health   *Health            // nil disables /readyz and grpc.health.v1
	Log      *slog.Logger
	Extra    map[string]http.Handler // dev-only HTTP routes mounted as-is
}

// GRPCInterceptors is the unary chain: request id + access log, then auth,
// then the per-tenant limiter.
func GRPCInterceptors(o Options) grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(unaryAccess(o.Log), UnaryAuth(o.Verifier), unaryLimit(o.Limiter))
}

func unaryAccess(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, srv *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		var given string
		if v := md.Get(RequestIDHeader); len(v) > 0 {
			given = v[0]
		}
		ri := &reqInfo{id: newRequestID(given)}
		grpc.SetHeader(ctx, metadata.Pairs(RequestIDHeader, ri.id))
		start := time.Now()
		metrics.InFlight.Inc()
		resp, err := h(withReqInfo(ctx, ri), req)
		metrics.InFlight.Dec()
		code := status.Code(err)
		record(log, ri, srv.FullMethod, code.String(), start, err)
		return resp, err
	}
}

func unaryLimit(l *ratelimit.Limiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if err := limit(ctx, l); err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
}

// limit runs after auth: the tenant claim is the bucket key.
func limit(ctx context.Context, l *ratelimit.Limiter) error {
	if l == nil {
		return nil
	}
	c, ok := auth.FromContext(ctx)
	if !ok {
		return nil
	}
	if ok, wait := l.Allow(c.Tenant); !ok {
		metrics.RateLimited.WithLabelValues(c.Tenant).Inc()
		grpc.SetHeader(ctx, metadata.Pairs("retry-after", strconv.Itoa(int(wait.Seconds())+1)))
		return status.Errorf(codes.ResourceExhausted, "tenant %s rate limited, retry in %s", c.Tenant, wait.Round(time.Millisecond))
	}
	return nil
}

func record(log *slog.Logger, ri *reqInfo, method, code string, start time.Time, err error) {
	d := time.Since(start)
	metrics.RequestDuration.WithLabelValues(method, code).Observe(d.Seconds())
	if log == nil {
		return
	}
	attrs := []any{"request_id", ri.id, "method", method, "tenant", ri.tenant, "code", code, "duration_ms", float64(d.Microseconds()) / 1e3}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	log.LogAttrs(context.Background(), slog.LevelInfo, "request", slog.Group("", attrs...))
}

// httpAccess is the HTTP twin of unaryAccess.
func httpAccess(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ri := &reqInfo{id: newRequestID(r.Header.Get(RequestIDHeader))}
		w.Header().Set(RequestIDHeader, ri.id)
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		metrics.InFlight.Inc()
		next.ServeHTTP(sw, r.WithContext(withReqInfo(r.Context(), ri)))
		metrics.InFlight.Dec()
		record(log, ri, r.Method+" "+r.URL.Path, strconv.Itoa(sw.code), start, nil)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }
