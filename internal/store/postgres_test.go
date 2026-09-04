//go:build integration

package store

import (
	"context"
	"os"
	"strings"
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
