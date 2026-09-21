// Package store persists policies, tenant rollout state and the audit chain.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

var (
	ErrNotFound = errors.New("not found")
	// ErrIdempotencyMismatch: same key was already used with a different policy body.
	ErrIdempotencyMismatch = errors.New("idempotency key reused with different payload")
)

type Policy struct {
	Tenant    string
	Version   int64
	Rego      string
	CreatedAt time.Time
}

// TenantState is the rollout state: which version is served and which (if
// any) is evaluated in shadow mode. 0 means none.
type TenantState struct {
	Active int64
	Shadow int64
}

type Store interface {
	// PutPolicy assigns the next version for the tenant. If idemKey was seen
	// before with the same rego it returns that policy and created=false.
	PutPolicy(ctx context.Context, tenant, rego, idemKey string) (p Policy, created bool, err error)
	GetPolicy(ctx context.Context, tenant string, version int64) (Policy, error)
	GetTenantState(ctx context.Context, tenant string) (TenantState, error)
	SetTenantState(ctx context.Context, tenant string, st TenantState) error
	// AppendAudit assigns Seq, PrevHash and Hash and persists the event.
	// Appends for one tenant are serialised so the chain has no forks.
	AppendAudit(ctx context.Context, ev *audit.Event) error
	// ListAudit returns up to limit events with seq > afterSeq, ascending.
	ListAudit(ctx context.Context, tenant string, afterSeq int64, limit int) ([]audit.Event, error)
	// Ping reports whether the backing store is reachable; readiness depends on it.
	Ping(ctx context.Context) error
	Close() error
}

// link fills in the chain fields given the previous event's (seq, hash).
func link(ev *audit.Event, prevSeq int64, prevHash string) {
	if prevHash == "" {
		prevHash = audit.Genesis
	}
	ev.Seq = prevSeq + 1
	ev.PrevHash = prevHash
	ev.Hash = audit.Hash(prevHash, *ev)
}
