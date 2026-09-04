// Package metrics registers the service's Prometheus collectors.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	Checks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gatekeeper_checks_total", Help: "Policy decisions by tenant and outcome.",
	}, []string{"tenant", "decision"})
	ShadowDivergence = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gatekeeper_shadow_divergence_total", Help: "Checks where the shadow policy disagreed with the active one.",
	}, []string{"tenant"})
	EvalDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "gatekeeper_eval_seconds", Help: "Rego evaluation latency.", Buckets: prometheus.ExponentialBuckets(1e-5, 4, 8),
	})
	AuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gatekeeper_auth_failures_total", Help: "Requests rejected by the JWT middleware.",
	})
	Errors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gatekeeper_errors_total", Help: "Internal errors by operation.",
	}, []string{"op"})
)
