// Package ratelimit is a per-key token bucket used to cap each tenant's
// request rate so one noisy tenant cannot starve the others.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter hands out `rate` tokens per second per key with a burst of `burst`.
// Buckets are created lazily and dropped by Sweep once idle.
type Limiter struct {
	rate, burst float64
	now         func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

func New(ratePerSec float64, burst int) *Limiter {
	return &Limiter{rate: ratePerSec, burst: float64(burst), now: time.Now, buckets: map[string]*bucket{}}
}

// Allow takes one token for key. When it cannot, it returns how long the
// caller should wait before a token will be available.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, max(wait, time.Millisecond)
}

// Sweep drops buckets untouched for longer than idle and returns how many remain.
// An idle bucket is full by construction, so dropping it changes nothing for the key.
func (l *Limiter) Sweep(idle time.Duration) int {
	cutoff := l.now().Add(-idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
	return len(l.buckets)
}

// SweepEvery runs Sweep in the background until stop is closed.
func (l *Limiter) SweepEvery(every, idle time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			l.Sweep(idle)
		case <-stop:
			return
		}
	}
}
