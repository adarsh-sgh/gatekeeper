package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/adarsh-sgh/gatekeeper/api/gatekeeper/v1"
	"github.com/adarsh-sgh/gatekeeper/internal/auth"
	"github.com/adarsh-sgh/gatekeeper/internal/metrics"
)

// UnaryAuth is the gRPC interceptor: it turns the bearer token in the
// `authorization` metadata into Claims on the context.
func UnaryAuth(v *auth.Verifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		var hdr string
		if vals := md.Get("authorization"); len(vals) > 0 {
			hdr = vals[0]
		}
		claims, err := verify(ctx, v, hdr)
		if err != nil {
			return nil, err
		}
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

// NewHTTPHandler mirrors the gRPC API as JSON over HTTP using the same
// request/response messages (protojson), plus /metrics and /healthz.
// extra lets main mount dev-only routes such as the embedded issuer's JWKS.
func NewHTTPHandler(svc *Service, v *auth.Verifier, extra map[string]http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	for pattern, h := range extra {
		mux.Handle(pattern, h)
	}
	mux.Handle("POST /v1/check", authed(v, handle(svc.Check, body(func() *pb.CheckRequest { return &pb.CheckRequest{} }))))
	mux.Handle("PUT /v1/policies", authed(v, handle(svc.PutPolicy, func(r *http.Request) (*pb.PutPolicyRequest, error) {
		req, err := body(func() *pb.PutPolicyRequest { return &pb.PutPolicyRequest{} })(r)
		if err == nil && req.IdempotencyKey == "" {
			req.IdempotencyKey = r.Header.Get("Idempotency-Key")
		}
		return req, err
	})))
	mux.Handle("POST /v1/policies/{version}/promote", authed(v, handle(svc.PromotePolicy, func(r *http.Request) (*pb.PromotePolicyRequest, error) {
		ver, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
		return &pb.PromotePolicyRequest{Version: ver}, err
	})))
	mux.Handle("GET /v1/audit", authed(v, handle(svc.ListAuditEvents, func(r *http.Request) (*pb.ListAuditEventsRequest, error) {
		after, _ := strconv.ParseInt(r.URL.Query().Get("after_seq"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		return &pb.ListAuditEventsRequest{AfterSeq: after, Limit: int32(limit)}, nil
	})))
	mux.Handle("GET /v1/audit/verify", authed(v, handle(svc.VerifyAuditChain, func(*http.Request) (*pb.VerifyAuditChainRequest, error) {
		return &pb.VerifyAuditChainRequest{}, nil
	})))
	return mux
}

func authed(v *auth.Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := verify(r.Context(), v, r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithClaims(r.Context(), claims)))
	})
}

func body[Req proto.Message](newReq func() Req) func(*http.Request) (Req, error) {
	return func(r *http.Request) (Req, error) {
		req := newReq()
		b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return req, err
		}
		return req, protojson.Unmarshal(b, req)
	}
}

func handle[Req, Resp proto.Message](rpc func(context.Context, Req) (Resp, error), parse func(*http.Request) (Req, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := parse(r)
		if err != nil {
			writeError(w, status.Errorf(codes.InvalidArgument, "bad request: %v", err))
			return
		}
		resp, err := rpc(r.Context(), req)
		if err != nil {
			writeError(w, err)
			return
		}
		out, _ := protojson.MarshalOptions{EmitDefaultValues: true}.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
}

var httpCodes = map[codes.Code]int{
	codes.InvalidArgument: 400, codes.Unauthenticated: 401, codes.PermissionDenied: 403,
	codes.NotFound: 404, codes.FailedPrecondition: 409,
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
