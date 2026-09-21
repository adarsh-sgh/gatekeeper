package main

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func get(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		return -1
	}
	resp.Body.Close()
	return resp.StatusCode
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// SIGTERM must flip readiness on both transports, keep serving for the drain
// window, then stop cleanly.
func TestSIGTERMDrainsBeforeStopping(t *testing.T) {
	started := make(chan [2]string, 1)
	c := config{grpcAddr: "127.0.0.1:0", httpAddr: "127.0.0.1:0", devIssuer: true,
		drainDelay: 300 * time.Millisecond, shutdownWindow: 2 * time.Second, started: started}
	done := make(chan error, 1)
	go func() { done <- run(c, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	var addrs [2]string
	select {
	case addrs = <-started:
	case err := <-done:
		t.Fatalf("run exited early: %v", err)
	}
	httpURL := "http://" + addrs[1]
	conn, err := grpc.NewClient(addrs[0], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hc := healthpb.NewHealthClient(conn)
	waitFor(t, "ready", 2*time.Second, func() bool { return get(t, httpURL+"/readyz") == 200 })
	if r, err := hc.Check(t.Context(), &healthpb.HealthCheckRequest{}); err != nil || r.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("grpc health before drain: %v %v", r, err)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "readiness to fail", time.Second, func() bool { return get(t, httpURL+"/readyz") == 503 })
	if r, _ := hc.Check(t.Context(), &healthpb.HealthCheckRequest{}); r.GetStatus() != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("grpc health during drain: %v", r)
	}
	if get(t, httpURL+"/healthz") != 200 {
		t.Fatal("must keep serving during the drain window")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return after drain")
	}
	if get(t, httpURL+"/healthz") != -1 {
		t.Fatal("listener still open after shutdown")
	}
}
