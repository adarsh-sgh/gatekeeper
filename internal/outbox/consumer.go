package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

// ConsumerSchema is owned by the consumer: the dedup ledger and the
// projection it maintains (per-tenant allow/deny counts).
const ConsumerSchema = `
CREATE TABLE IF NOT EXISTS consumer_processed (
    consumer text NOT NULL,
    event_id text NOT NULL,
    PRIMARY KEY (consumer, event_id)
);
CREATE TABLE IF NOT EXISTS decision_stats (
    consumer text   NOT NULL,
    tenant   text   NOT NULL,
    allowed  bigint NOT NULL,
    denied   bigint NOT NULL,
    PRIMARY KEY (consumer, tenant)
);`

// Consumer reads the audit topic in a consumer group with auto-commit off.
// Each fetched batch is applied in one statement that records event ids in
// the ledger and bumps counters only for ids not seen before; offsets are
// committed after it. A crash before the commit redelivers the batch, and
// the ledger turns the redelivery into a no-op.
type Consumer struct {
	Pool  *pgxpool.Pool
	Kafka *kgo.Client // with ConsumerGroup, ConsumeTopics, DisableAutoCommit
	Name  string
	Log   *slog.Logger
	// AfterApply runs after the batch's DB effect committed and before the
	// offsets are: the redelivery window. Tests crash there.
	AfterApply func(applied, skipped int)
}

// apply dedups within the batch (DISTINCT ON) and against the ledger
// (ON CONFLICT DO NOTHING), then counts only newly recorded events.
// Data-modifying CTEs all run, so this is one atomic round trip.
const applySQL = `
WITH incoming AS (
    SELECT DISTINCT ON (event_id) event_id, tenant, allowed
    FROM unnest($2::text[], $3::text[], $4::bool[]) AS t(event_id, tenant, allowed)
), fresh AS (
    INSERT INTO consumer_processed (consumer, event_id) SELECT $1, event_id FROM incoming
    ON CONFLICT DO NOTHING RETURNING event_id
), counted AS (
    INSERT INTO decision_stats (consumer, tenant, allowed, denied)
    SELECT $1, tenant, count(*) FILTER (WHERE allowed), count(*) FILTER (WHERE NOT allowed)
    FROM incoming JOIN fresh USING (event_id) GROUP BY tenant
    ON CONFLICT (consumer, tenant) DO UPDATE
    SET allowed = decision_stats.allowed + EXCLUDED.allowed, denied = decision_stats.denied + EXCLUDED.denied
    RETURNING 1
)
SELECT count(*) FROM fresh`

func (c *Consumer) Run(ctx context.Context) error {
	if _, err := c.Pool.Exec(ctx, ConsumerSchema); err != nil {
		return fmt.Errorf("consumer schema: %w", err)
	}
	for {
		fs := c.Kafka.PollFetches(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err := fs.Err0(); err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
		recs := fs.Records()
		if len(recs) == 0 {
			continue
		}
		ids, tenants, allowed := make([]string, len(recs)), make([]string, len(recs)), make([]bool, len(recs))
		for i, r := range recs {
			var env audit.Envelope
			if err := json.Unmarshal(r.Value, &env); err != nil || env.EventID == "" {
				// A poison message would block the partition forever; fail loudly instead.
				return fmt.Errorf("decode %s/%d@%d: %v", r.Topic, r.Partition, r.Offset, err)
			}
			ids[i], tenants[i], allowed[i] = env.EventID, env.Event.Tenant, env.Event.Allowed
		}
		var applied int
		if err := c.Pool.QueryRow(ctx, applySQL, c.Name, ids, tenants, allowed).Scan(&applied); err != nil {
			return fmt.Errorf("apply: %w", err)
		}
		skipped := len(recs) - applied
		if c.AfterApply != nil {
			c.AfterApply(applied, skipped)
		}
		if err := c.Kafka.CommitRecords(ctx, recs...); err != nil {
			return fmt.Errorf("commit offsets: %w", err)
		}
		c.Log.Info("batch", "records", len(recs), "applied", applied, "skipped", skipped)
	}
}
