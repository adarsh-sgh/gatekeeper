package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

// runSuite is the conformance suite every Store implementation must pass.
func runSuite(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := fmt.Sprintf("t-%d", time.Now().UnixNano()) // unique per run so Postgres reruns are clean

	t.Run("policy versions and idempotency", func(t *testing.T) {
		p1, created, err := s.PutPolicy(ctx, tenant, "package gatekeeper\nallow := true", "k1")
		if err != nil || !created || p1.Version != 1 {
			t.Fatalf("first put: %+v created=%v err=%v", p1, created, err)
		}
		again, created, err := s.PutPolicy(ctx, tenant, "package gatekeeper\nallow := true", "k1")
		if err != nil || created || again.Version != 1 {
			t.Fatalf("replay: %+v created=%v err=%v", again, created, err)
		}
		if _, _, err := s.PutPolicy(ctx, tenant, "package gatekeeper\nallow := false", "k1"); !errors.Is(err, ErrIdempotencyMismatch) {
			t.Fatalf("mismatch: err=%v", err)
		}
		p2, _, err := s.PutPolicy(ctx, tenant, "package gatekeeper\nallow := false", "")
		if err != nil || p2.Version != 2 {
			t.Fatalf("second put: %+v err=%v", p2, err)
		}
		if got, err := s.GetPolicy(ctx, tenant, 2); err != nil || got.Rego != p2.Rego {
			t.Fatalf("get v2: %+v err=%v", got, err)
		}
		if _, err := s.GetPolicy(ctx, tenant, 9); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get v9: err=%v", err)
		}
		// Other tenants have their own version space.
		if p, _, _ := s.PutPolicy(ctx, tenant+"-other", "package gatekeeper", "k1"); p.Version != 1 {
			t.Fatalf("other tenant version = %d", p.Version)
		}
	})

	t.Run("tenant state", func(t *testing.T) {
		if st, err := s.GetTenantState(ctx, tenant); err != nil || st != (TenantState{}) {
			t.Fatalf("fresh tenant: %+v err=%v", st, err)
		}
		want := TenantState{Active: 1, Shadow: 2}
		if err := s.SetTenantState(ctx, tenant, want); err != nil {
			t.Fatal(err)
		}
		if err := s.SetTenantState(ctx, tenant, want); err != nil { // upsert
			t.Fatal(err)
		}
		if st, _ := s.GetTenantState(ctx, tenant); st != want {
			t.Fatalf("state = %+v", st)
		}
	})

	t.Run("audit chain under concurrent appends", func(t *testing.T) {
		const n = 40
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ev := &audit.Event{TS: time.Now(), Tenant: tenant, Caller: "svc", Action: "read",
					Subject:  audit.Subject{ID: fmt.Sprint("u", i), Attrs: map[string]any{"n": float64(i)}},
					Resource: audit.Resource{Type: "doc", ID: "d"}, PolicyVersion: 1, Allowed: i%3 == 0, Reason: "r"}
				errs <- s.AppendAudit(ctx, ev)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		var all []audit.Event
		for after := int64(0); ; {
			page, err := s.ListAudit(ctx, tenant, after, 7)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) == 0 {
				break
			}
			all = append(all, page...)
			after = page[len(page)-1].Seq
		}
		if len(all) != n {
			t.Fatalf("got %d events, want %d", len(all), n)
		}
		if broken := audit.Verify(all); broken != 0 {
			t.Fatalf("chain broken at %d", broken)
		}
		if all[0].PrevHash != audit.Genesis || all[0].Subject.Attrs["n"] == nil {
			t.Fatalf("first event round-trip: %+v", all[0])
		}
	})
}

func TestMemoryStore(t *testing.T) { runSuite(t, NewMemory()) }
