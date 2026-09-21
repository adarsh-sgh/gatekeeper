package store

import (
	"context"
	"sync"
	"time"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

// Memory is the reference implementation used by unit tests and `-dev` mode.
type Memory struct {
	mu       sync.Mutex
	policies map[string][]Policy // tenant -> versions (index = version-1)
	idem     map[string]Policy   // tenant+"\x00"+key
	tenants  map[string]TenantState
	events   map[string][]audit.Event
}

func NewMemory() *Memory {
	return &Memory{policies: map[string][]Policy{}, idem: map[string]Policy{},
		tenants: map[string]TenantState{}, events: map[string][]audit.Event{}}
}

func (m *Memory) PutPolicy(_ context.Context, tenant, rego, idemKey string) (Policy, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ik := tenant + "\x00" + idemKey
	if idemKey != "" {
		if p, ok := m.idem[ik]; ok {
			if p.Rego != rego {
				return Policy{}, false, ErrIdempotencyMismatch
			}
			return p, false, nil
		}
	}
	p := Policy{Tenant: tenant, Version: int64(len(m.policies[tenant]) + 1), Rego: rego, CreatedAt: time.Now().UTC()}
	m.policies[tenant] = append(m.policies[tenant], p)
	if idemKey != "" {
		m.idem[ik] = p
	}
	return p, true, nil
}

func (m *Memory) GetPolicy(_ context.Context, tenant string, version int64) (Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps := m.policies[tenant]
	if version < 1 || int(version) > len(ps) {
		return Policy{}, ErrNotFound
	}
	return ps[version-1], nil
}

func (m *Memory) GetTenantState(_ context.Context, tenant string) (TenantState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tenants[tenant], nil
}

func (m *Memory) SetTenantState(_ context.Context, tenant string, st TenantState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenants[tenant] = st
	return nil
}

func (m *Memory) AppendAudit(_ context.Context, ev *audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	evs := m.events[ev.Tenant]
	if n := len(evs); n == 0 {
		link(ev, 0, audit.Genesis)
	} else {
		link(ev, evs[n-1].Seq, evs[n-1].Hash)
	}
	m.events[ev.Tenant] = append(evs, *ev)
	return nil
}

func (m *Memory) ListAudit(_ context.Context, tenant string, afterSeq int64, limit int) ([]audit.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	evs := m.events[tenant]
	start := min(int(afterSeq), len(evs)) // seq == index+1
	end := min(start+limit, len(evs))
	return append([]audit.Event(nil), evs[start:end]...), nil
}

func (m *Memory) Ping(context.Context) error { return nil }

func (m *Memory) Close() error { return nil }
