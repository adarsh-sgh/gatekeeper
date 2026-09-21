package server

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/adarsh-sgh/gatekeeper/internal/store"
)

var errDraining = errors.New("draining")

// Health serves liveness and readiness on both transports. Liveness is "the
// process is up"; readiness is "the store answers and we are not draining",
// which is what a load balancer or kubelet should route on.
type Health struct {
	store    store.Store
	grpc     *health.Server
	draining atomic.Bool
}

func NewHealth(st store.Store) *Health {
	h := &Health{store: st, grpc: health.NewServer()}
	h.grpc.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	return h
}

// Register mounts grpc.health.v1 so `grpc_health_probe` and k8s gRPC probes work.
func (h *Health) Register(gs *grpc.Server) { healthpb.RegisterHealthServer(gs, h.grpc) }

// Ready is nil when the service should receive traffic.
func (h *Health) Ready(ctx context.Context) error {
	if h.draining.Load() {
		return errDraining
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return h.store.Ping(ctx)
}

// Drain flips readiness to failing on both transports. Listeners stay open;
// the caller waits for upstreams to notice before it stops accepting.
func (h *Health) Drain() {
	h.draining.Store(true)
	h.grpc.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
}

func (h *Health) Draining() bool { return h.draining.Load() }

func (h *Health) readyz(w http.ResponseWriter, r *http.Request) {
	if err := h.Ready(r.Context()); err != nil {
		http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready\n"))
}
