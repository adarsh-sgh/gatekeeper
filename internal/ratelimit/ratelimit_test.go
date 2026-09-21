package ratelimit

import (
	"testing"
	"time"
)

// Burst, refill, per-key isolation and idle sweep on one fake clock.
func TestTokenBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(10, 3) // 10/s, burst 3
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("acme"); !ok {
			t.Fatalf("burst request %d rejected", i)
		}
	}
	ok, wait := l.Allow("acme")
	if ok || wait < 90*time.Millisecond || wait > 110*time.Millisecond {
		t.Fatalf("4th request: ok=%v wait=%v, want rejected ~100ms", ok, wait)
	}
	if ok, _ := l.Allow("globex"); !ok {
		t.Fatal("other tenant must have its own bucket")
	}

	now = now.Add(250 * time.Millisecond) // 2.5 tokens refilled
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow("acme"); !ok {
			t.Fatalf("after refill request %d rejected", i)
		}
	}
	if ok, _ := l.Allow("acme"); ok {
		t.Fatal("half a token must not admit a request")
	}

	now = now.Add(10 * time.Second) // bucket caps at burst, not 100 tokens
	for i := 0; i < 3; i++ {
		l.Allow("acme")
	}
	if ok, _ := l.Allow("acme"); ok {
		t.Fatal("bucket exceeded burst after long idle")
	}

	if n := l.Sweep(time.Second); n != 1 { // globex idle >1s, acme just used
		t.Fatalf("sweep left %d buckets, want 1", n)
	}
	now = now.Add(2 * time.Second)
	if n := l.Sweep(time.Second); n != 0 {
		t.Fatalf("sweep left %d buckets, want 0", n)
	}
	if ok, _ := l.Allow("acme"); !ok {
		t.Fatal("swept key must start with a full bucket")
	}
}
