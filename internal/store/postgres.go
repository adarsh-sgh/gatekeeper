package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

//go:embed schema.sql
var schema string

type Postgres struct {
	pool   *pgxpool.Pool
	outbox bool

	// Chain heads this process last wrote or read, plus a per-tenant mutex so
	// goroutines in one process never race each other to the same seq.
	mu    sync.Mutex
	heads map[string]head
	locks map[string]*sync.Mutex
}

type head struct {
	seq  int64
	hash string
}

// Option configures NewPostgres.
type Option func(*Postgres)

// WithOutbox writes every audit event to audit_outbox in the same statement
// (hence the same transaction) as the audit row.
func WithOutbox() Option { return func(p *Postgres) { p.outbox = true } }

// NewPostgres connects and applies schema.sql (idempotent).
func NewPostgres(ctx context.Context, dsn string, opts ...Option) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	p := &Postgres{pool: pool, heads: map[string]head{}, locks: map[string]*sync.Mutex{}}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *Postgres) Close() error { p.pool.Close(); return nil }

// tx runs fn under a transaction holding a per-tenant advisory lock, which
// serialises version assignment and audit appends for that tenant only.
func (p *Postgres) tx(ctx context.Context, tenant string, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenant); err != nil {
			return err
		}
		return fn(tx)
	})
}

func (p *Postgres) PutPolicy(ctx context.Context, tenant, rego, idemKey string) (pol Policy, created bool, err error) {
	err = p.tx(ctx, tenant, func(tx pgx.Tx) error {
		if idemKey != "" {
			err := tx.QueryRow(ctx, `SELECT tenant, version, rego, created_at FROM policies WHERE tenant=$1 AND idempotency_key=$2`,
				tenant, idemKey).Scan(&pol.Tenant, &pol.Version, &pol.Rego, &pol.CreatedAt)
			if err == nil {
				if pol.Rego != rego {
					return ErrIdempotencyMismatch
				}
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		var key *string
		if idemKey != "" {
			key = &idemKey
		}
		created = true
		return tx.QueryRow(ctx, `INSERT INTO policies (tenant, version, rego, idempotency_key)
			VALUES ($1, (SELECT coalesce(max(version),0)+1 FROM policies WHERE tenant=$1), $2, $3)
			RETURNING tenant, version, rego, created_at`, tenant, rego, key).
			Scan(&pol.Tenant, &pol.Version, &pol.Rego, &pol.CreatedAt)
	})
	return pol, created, err
}

func (p *Postgres) GetPolicy(ctx context.Context, tenant string, version int64) (Policy, error) {
	var pol Policy
	err := p.pool.QueryRow(ctx, `SELECT tenant, version, rego, created_at FROM policies WHERE tenant=$1 AND version=$2`,
		tenant, version).Scan(&pol.Tenant, &pol.Version, &pol.Rego, &pol.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	return pol, err
}

func (p *Postgres) GetTenantState(ctx context.Context, tenant string) (TenantState, error) {
	var st TenantState
	// One round trip on the Check hot path for rollout state and kill switch.
	err := p.pool.QueryRow(ctx, `SELECT coalesce(t.active_version,0), coalesce(t.shadow_version,0), coalesce(r.disabled,false)
		FROM (SELECT $1::text AS tenant) k LEFT JOIN tenants t USING (tenant) LEFT JOIN tenant_registry r USING (tenant)`, tenant).
		Scan(&st.Active, &st.Shadow, &st.Disabled)
	return st, err
}

func (p *Postgres) PutTenant(ctx context.Context, t Tenant) (Tenant, error) {
	err := p.pool.QueryRow(ctx, `INSERT INTO tenant_registry (tenant, display_name, disabled) VALUES ($1,$2,$3)
		ON CONFLICT (tenant) DO UPDATE SET display_name=EXCLUDED.display_name, disabled=EXCLUDED.disabled
		RETURNING created_at`, t.Name, t.DisplayName, t.Disabled).Scan(&t.CreatedAt)
	return t, err
}

func (p *Postgres) GetTenant(ctx context.Context, name string) (Tenant, error) {
	t := Tenant{Name: name}
	err := p.pool.QueryRow(ctx, `SELECT display_name, disabled, created_at FROM tenant_registry WHERE tenant=$1`, name).
		Scan(&t.DisplayName, &t.Disabled, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	return t, err
}

func (p *Postgres) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := p.pool.Query(ctx, `SELECT tenant, display_name, disabled, created_at FROM tenant_registry ORDER BY tenant`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Tenant, error) {
		var t Tenant
		return t, r.Scan(&t.Name, &t.DisplayName, &t.Disabled, &t.CreatedAt)
	})
}

func (p *Postgres) DeleteTenant(ctx context.Context, name string) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM tenant_registry WHERE tenant=$1`, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `DELETE FROM tenants WHERE tenant=$1`, name)
		return err
	})
}

func (p *Postgres) SetTenantState(ctx context.Context, tenant string, st TenantState) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO tenants (tenant, active_version, shadow_version) VALUES ($1,$2,$3)
		ON CONFLICT (tenant) DO UPDATE SET active_version=EXCLUDED.active_version, shadow_version=EXCLUDED.shadow_version`,
		tenant, st.Active, st.Shadow)
	return err
}

// optimisticTries is how often an append races on the fast path before it
// falls back to the advisory-locked transaction, which always makes progress.
const optimisticTries = 3

const uniqueViolation = "23505" // Postgres SQLSTATE

// AppendAudit links to the cached chain head and INSERTs in one round trip.
// The (tenant, seq) primary key is the arbiter: a unique violation means
// another instance appended first, so the head is reloaded and the insert
// retried; after optimisticTries losses the append takes the tenant's
// advisory lock in a transaction instead. The fast path inserts only if it
// can try-lock that same key, so a slow-path writer is never overtaken.
// Within a process a per-tenant mutex avoids self-inflicted races.
func (p *Postgres) AppendAudit(ctx context.Context, ev *audit.Event) error {
	lock := p.tenantLock(ev.Tenant)
	lock.Lock()
	defer lock.Unlock()
	for attempt := 0; attempt < optimisticTries; attempt++ {
		h, ok := p.cachedHead(ev.Tenant)
		if !ok {
			var err error
			if h, err = p.readHead(ctx, p.pool, ev.Tenant); err != nil {
				return err
			}
		}
		n, err := p.insert(ctx, p.pool, ev, h, true)
		if err == nil && n == 1 {
			return nil
		}
		p.forgetHead(ev.Tenant)
		var pgErr *pgconn.PgError
		if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != uniqueViolation) {
			return err
		}
		if n == 0 { // a slow-path writer holds the lock; let it finish
			select {
			case <-time.After(time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return p.tx(ctx, ev.Tenant, func(tx pgx.Tx) error {
		h, err := p.readHead(ctx, tx, ev.Tenant)
		if err != nil {
			return err
		}
		_, err = p.insert(ctx, tx, ev, h, false)
		return err
	})
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (p *Postgres) readHead(ctx context.Context, q querier, tenant string) (head, error) {
	var h head
	err := q.QueryRow(ctx, `SELECT seq, hash FROM audit_events WHERE tenant=$1 ORDER BY seq DESC LIMIT 1`, tenant).Scan(&h.seq, &h.hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return head{}, err
	}
	return h, nil
}

const insertAudit = `INSERT INTO audit_events
		(tenant, seq, ts, caller, subject, action, resource, policy_version, allowed, reason,
		 shadow_version, shadow_allowed, shadow_diverged, prev_hash, hash)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15 `

// insert links ev after h and writes it, returning rows inserted (0 when
// tryLock is set and the tenant's advisory lock is held elsewhere). With the
// outbox on, the outbox row is inserted by the same statement from the audit
// row's RETURNING, so it exists iff the audit row does; still one round trip.
func (p *Postgres) insert(ctx context.Context, q querier, ev *audit.Event, h head, tryLock bool) (int64, error) {
	link(ev, h.seq, h.hash)
	subj, _ := json.Marshal(ev.Subject)
	res, _ := json.Marshal(ev.Resource)
	guard := ""
	if tryLock {
		guard = `WHERE pg_try_advisory_xact_lock(hashtext($1))`
	}
	sql, args := insertAudit+guard, []any{ev.Tenant, ev.Seq, ev.TS, ev.Caller, subj, ev.Action, res, ev.PolicyVersion,
		ev.Allowed, ev.Reason, ev.ShadowVersion, ev.ShadowAllowed, ev.ShadowDiverge, ev.PrevHash, ev.Hash}
	if p.outbox {
		id := audit.EventID(ev.Tenant, ev.Seq)
		payload, err := json.Marshal(audit.Envelope{EventID: id, PrevHash: ev.PrevHash, Hash: ev.Hash, Event: *ev})
		if err != nil {
			return 0, err
		}
		sql = `WITH ev AS (` + sql + ` RETURNING tenant)
		INSERT INTO audit_outbox (event_id, tenant, payload) SELECT $16, tenant, $17 FROM ev`
		args = append(args, id, payload)
	}
	tag, err := q.Exec(ctx, sql, args...)
	if err == nil && tag.RowsAffected() == 1 {
		p.setHead(ev.Tenant, head{ev.Seq, ev.Hash})
	}
	return tag.RowsAffected(), err
}

func (p *Postgres) tenantLock(tenant string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.locks[tenant]
	if l == nil {
		l = &sync.Mutex{}
		p.locks[tenant] = l
	}
	return l
}

func (p *Postgres) cachedHead(tenant string) (head, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.heads[tenant]
	return h, ok
}

func (p *Postgres) setHead(tenant string, h head) {
	p.mu.Lock()
	p.heads[tenant] = h
	p.mu.Unlock()
}

func (p *Postgres) forgetHead(tenant string) {
	p.mu.Lock()
	delete(p.heads, tenant)
	p.mu.Unlock()
}

func (p *Postgres) ListAudit(ctx context.Context, tenant string, afterSeq int64, limit int) ([]audit.Event, error) {
	rows, err := p.pool.Query(ctx, `SELECT seq, ts, caller, subject, action, resource, policy_version, allowed, reason,
		shadow_version, shadow_allowed, shadow_diverged, prev_hash, hash
		FROM audit_events WHERE tenant=$1 AND seq>$2 ORDER BY seq LIMIT $3`, tenant, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Event
	for rows.Next() {
		ev := audit.Event{Tenant: tenant}
		var subj, res []byte
		if err := rows.Scan(&ev.Seq, &ev.TS, &ev.Caller, &subj, &ev.Action, &res, &ev.PolicyVersion, &ev.Allowed, &ev.Reason,
			&ev.ShadowVersion, &ev.ShadowAllowed, &ev.ShadowDiverge, &ev.PrevHash, &ev.Hash); err != nil {
			return nil, err
		}
		if err := errors.Join(json.Unmarshal(subj, &ev.Subject), json.Unmarshal(res, &ev.Resource)); err != nil {
			return nil, err
		}
		ev.TS = ev.TS.UTC()
		out = append(out, ev)
	}
	return out, rows.Err()
}
