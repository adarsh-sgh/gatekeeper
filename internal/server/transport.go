package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/metrics"
	"github.com/adarsh-sgh/gatekeeper/internal/ratelimit"
)

// UnaryAuth is the gRPC interceptor: it turns the bearer token in the
// `authorization` metadata into Claims on the context.
func UnaryAuth(v *auth.Verifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, srv *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if strings.HasPrefix(srv.FullMethod, "/grpc.health.v1.Health/") || strings.HasPrefix(srv.FullMethod, ExtAuthzMethodPrefix) {
			return h(ctx, req) // probes carry no token; ext_authz verifies the forwarded one
		}
		md, _ := metadata.FromIncomingContext(ctx)
		var hdr string
		if vals := md.Get("authorization"); len(vals) > 0 {
			hdr = vals[0]
		}
		claims, err := verify(ctx, v, hdr)
		if err != nil {
			return nil, err
		}
		setTenant(ctx, claims.Tenant)
		return h(auth.WithClaims(ctx, claims), req)
	}
}

func verify(ctx context.Context, v *auth.Verifier, header string) (*auth.Claims, error) {
	tok, ok := auth.Bearer(header)
	if !ok {
		metrics.AuthFailures.Inc()
		return nil, status.Error(codes.Unauthenticated, "missing bearer token")
	}
	claims, err := v.Verify(ctx, tok)
	if err != nil {
		metrics.AuthFailures.Inc()
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}
	return claims, nil
}

// NewHTTPHandler serves the grpc-gateway routes generated from the proto's
// google.api.http annotations, in process (no gRPC hop), behind the same
// request id, access log, auth and tenant limiter as gRPC; plus /metrics,
// /healthz and /readyz.
func NewHTTPHandler(svc *Service, o Options) http.Handler {
	gw := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{MarshalOptions: protojson.MarshalOptions{EmitDefaultValues: true}}),
		runtime.WithIncomingHeaderMatcher(func(h string) (string, bool) {
			if strings.EqualFold(h, "Idempotency-Key") {
				return "idempotency-key", true
			}
			return runtime.DefaultHeaderMatcher(h)
		}),
		runtime.WithErrorHandler(func(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
			writeError(w, err)
		}),
	)
	if err := pb.RegisterGatekeeperHandlerServer(context.Background(), gw, svc); err != nil {
		panic(err) // only on a nil server
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	if o.Health != nil {
		mux.HandleFunc("GET /readyz", o.Health.readyz)
	}
	for pattern, h := range o.Extra {
		mux.Handle(pattern, h)
	}
	mux.Handle("/v1/", httpAccess(o.Log, authedLimited(o.Verifier, o.Limiter, gw)))
	return mux
}

func authedLimited(v *auth.Verifier, l *ratelimit.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := verify(r.Context(), v, r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, err)
			return
		}
		ctx := auth.WithClaims(r.Context(), claims)
		setTenant(ctx, claims.Tenant)
		if l != nil {
			if ok, wait := l.Allow(claims.Tenant); !ok {
				metrics.RateLimited.WithLabelValues(claims.Tenant).Inc()
				w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
				writeError(w, status.Errorf(codes.ResourceExhausted, "tenant %s rate limited, retry in %s", claims.Tenant, wait.Round(time.Millisecond)))
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var httpCodes = map[codes.Code]int{
	codes.InvalidArgument: 400, codes.Unauthenticated: 401, codes.PermissionDenied: 403,
	codes.NotFound: 404, codes.FailedPrecondition: 409, codes.ResourceExhausted: 429,
	codes.Unavailable: 503, codes.Unimplemented: 501,
}

func writeError(w http.ResponseWriter, err error) {
	st, _ := status.FromError(err)
	code, ok := httpCodes[st.Code()]
	if !ok {
		code = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": st.Message(), "code": st.Code().String()})
}
