//go:build integration

package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

func pg(t *testing.T) *Postgres {
	dsn := os.Getenv("PG_DSN")
	if dsn == "" {
		t.Skip("PG_DSN not set")
	}
	s, err := NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPostgresStore(t *testing.T) { runSuite(t, pg(t)) }

// Two instances (separate pools, separate head caches) append to one tenant
// at once: the PK race is lost and retried, and the chain still verifies.
func TestPostgresAppendAcrossInstances(t *testing.T) {
	a, b := pg(t), pg(t)
	ctx := context.Background()
	tenant := "multi-" + time.Now().Format("150405.000000")
	const perInstance = 50
	var wg sync.WaitGroup
	errs := make(chan error, 2*perInstance)
	for _, s := range []*Postgres{a, b} {
		for i := range perInstance {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- s.AppendAudit(ctx, &audit.Event{TS: time.Now(), Tenant: tenant, Caller: "svc", Action: "read",
					Subject: audit.Subject{ID: fmt.Sprint("u", i)}, Resource: audit.Resource{Type: "doc"}, PolicyVersion: 1})
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	evs, err := a.ListAudit(ctx, tenant, 0, 1000)
	if err != nil || len(evs) != 2*perInstance {
		t.Fatalf("got %d events err=%v", len(evs), err)
	}
	if broken := audit.Verify(evs); broken != 0 {
		t.Fatalf("chain broken at %d", broken)
	}
}

// The DB rejects edits outright; if someone bypasses the trigger, Verify catches it.
func TestPostgresAuditIsTamperEvident(t *testing.T) {
	s := pg(t)
	ctx := context.Background()
	tenant := "tamper-" + time.Now().Format("150405.000000")
	for i := range 3 {
		ev := &audit.Event{TS: time.Now(), Tenant: tenant, Caller: "svc", Action: "read", Allowed: i == 1,
			Subject: audit.Subject{ID: "u"}, Resource: audit.Resource{Type: "doc", ID: "d"}, PolicyVersion: 1}
		if err := s.AppendAudit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.pool.Exec(ctx, `UPDATE audit_events SET allowed = true WHERE tenant=$1 AND seq=2`, tenant)
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update should be rejected by trigger, got %v", err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE tenant=$1 AND seq=3`, tenant); err == nil {
		t.Fatal("delete should be rejected by trigger")
	}

	// Simulate a privileged tamper: bypass the trigger and flip a decision.
	for _, q := range []string{
		`ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_modify`,
		`UPDATE audit_events SET allowed = NOT allowed WHERE tenant='` + tenant + `' AND seq=2`,
		`ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_modify`,
	} {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := s.ListAudit(ctx, tenant, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if broken := audit.Verify(evs); broken != 2 {
		t.Fatalf("Verify = %d, want 2", broken)
	}
}

// With the outbox on, racing instances (PK conflicts, retries, the locked
// slow path) still leave exactly one outbox row per committed audit event,
// carrying that event's id and hash.
func TestPostgresOutboxMatchesAudit(t *testing.T) {
	dsn := os.Getenv("PG_DSN")
	if dsn == "" {
		t.Skip("PG_DSN not set")
	}
	var insts []*Postgres
	for range 2 {
		s, err := NewPostgres(context.Background(), dsn, WithOutbox())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		insts = append(insts, s)
	}
	ctx := context.Background()
	tenant := "outbox-" + time.Now().Format("150405.000000")
	var wg sync.WaitGroup
	for _, s := range insts {
		for i := range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := s.AppendAudit(ctx, &audit.Event{TS: time.Now(), Tenant: tenant, Caller: "svc", Action: "read",
					Subject: audit.Subject{ID: fmt.Sprint("u", i)}, Resource: audit.Resource{Type: "doc"}, Allowed: i%2 == 0}); err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	evs, err := insts[0].ListAudit(ctx, tenant, 0, 1000)
	if err != nil || len(evs) != 100 {
		t.Fatalf("events: %d %v", len(evs), err)
	}
	rows, err := insts[0].pool.Query(ctx, `SELECT event_id, payload FROM audit_outbox WHERE tenant=$1 ORDER BY id`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]audit.Envelope{}
	for rows.Next() {
		var id string
		var env audit.Envelope
		if err := rows.Scan(&id, &env); err != nil {
			t.Fatal(err)
		}
		if _, dup := byID[id]; dup || id != env.EventID {
			t.Fatalf("outbox row %s duplicated or mismatched (%s)", id, env.EventID)
		}
		byID[id] = env
	}
	if len(byID) != len(evs) {
		t.Fatalf("outbox has %d rows for %d events", len(byID), len(evs))
	}
	for _, e := range evs {
		if env := byID[audit.EventID(tenant, e.Seq)]; env.Hash != e.Hash || env.Event.Allowed != e.Allowed {
			t.Fatalf("seq %d: outbox %+v vs audit hash %s", e.Seq, env, e.Hash)
		}
	}
	insts[0].pool.Exec(ctx, `DELETE FROM audit_outbox WHERE tenant=$1`, tenant)
}
