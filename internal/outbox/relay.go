// Package outbox moves audit events from Postgres to Kafka and applies them
// downstream exactly once in effect.
//
// The audit row and its audit_outbox row are written by one statement
// (store.WithOutbox), so an event is published iff it was committed. The
// Relay publishes outbox rows in id order and deletes them only after the
// broker acks; a crash in between republishes the batch (at-least-once).
// The Consumer deduplicates on event id in the same transaction as its
// side effect, which turns at-least-once delivery into an exactly-once effect.
package outbox

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/twmb/franz-go/pkg/kgo"
)

// leaderLock is the session advisory lock that makes one relay active; a
// standby takes over when the leader's connection drops (crash, SIGKILL).
const leaderLock = 0x67617465 // "gate"

type Relay struct {
	DSN   string
	Kafka *kgo.Client
	Topic string
	Batch int
	Poll  time.Duration
	Log   *slog.Logger
	// AfterPublish runs after the broker acked a batch and before its rows
	// are deleted: the window in which a crash causes duplicates. Tests use
	// it to crash there deterministically.
	AfterPublish func(published int)
}

// Run relays until ctx is done, reconnecting (and re-electing) on errors.
func (r *Relay) Run(ctx context.Context) error {
	for {
		err := r.lead(ctx)
		if ctx.Err() != nil {
			return nil
		}
		r.Log.Warn("relay error, reconnecting", "err", err)
		if !sleep(ctx, time.Second) {
			return nil
		}
	}
}

func (r *Relay) lead(ctx context.Context) error {
	conn, err := pgx.Connect(ctx, r.DSN)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background()) // closing the session releases the lock
	for {
		var leader bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, leaderLock).Scan(&leader); err != nil {
			return err
		}
		if leader {
			break
		}
		if !sleep(ctx, time.Second) {
			return ctx.Err()
		}
	}
	r.Log.Info("relay is leader")
	for {
		n, err := r.pump(ctx, conn)
		if err != nil {
			return err
		}
		if n < r.Batch && !sleep(ctx, r.Poll) {
			return ctx.Err()
		}
	}
}

func (r *Relay) pump(ctx context.Context, conn *pgx.Conn) (int, error) {
	rows, err := conn.Query(ctx, `SELECT id, event_id, tenant, payload FROM audit_outbox ORDER BY id LIMIT $1`, r.Batch)
	if err != nil {
		return 0, err
	}
	var ids []int64
	var recs []*kgo.Record
	for rows.Next() {
		var id int64
		var eventID, tenant string
		var payload []byte
		if err := rows.Scan(&id, &eventID, &tenant, &payload); err != nil {
			return 0, err
		}
		ids = append(ids, id)
		// Keyed by tenant: one partition per tenant keeps its chain in order.
		recs = append(recs, &kgo.Record{Topic: r.Topic, Key: []byte(tenant), Value: payload,
			Headers: []kgo.RecordHeader{{Key: "event_id", Value: []byte(eventID)}}})
	}
	if err := rows.Err(); err != nil || len(recs) == 0 {
		return 0, err
	}
	if err := r.Kafka.ProduceSync(ctx, recs...).FirstErr(); err != nil {
		return 0, fmt.Errorf("produce: %w", err)
	}
	if r.AfterPublish != nil {
		r.AfterPublish(len(recs))
	}
	if _, err := conn.Exec(ctx, `DELETE FROM audit_outbox WHERE id = ANY($1)`, ids); err != nil {
		return 0, fmt.Errorf("delete relayed rows: %w", err)
	}
	return len(recs), nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}
