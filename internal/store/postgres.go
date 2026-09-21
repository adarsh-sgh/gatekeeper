package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/adarsh-sgh/gatekeeper/internal/audit"
)

//go:embed schema.sql
var schema string

type Postgres struct{ pool *pgxpool.Pool }

// NewPostgres connects and applies schema.sql (idempotent).
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
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
	err := p.pool.QueryRow(ctx, `SELECT active_version, shadow_version FROM tenants WHERE tenant=$1`, tenant).
		Scan(&st.Active, &st.Shadow)
	if errors.Is(err, pgx.ErrNoRows) {
		return TenantState{}, nil
	}
	return st, err
}

func (p *Postgres) SetTenantState(ctx context.Context, tenant string, st TenantState) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO tenants (tenant, active_version, shadow_version) VALUES ($1,$2,$3)
		ON CONFLICT (tenant) DO UPDATE SET active_version=EXCLUDED.active_version, shadow_version=EXCLUDED.shadow_version`,
		tenant, st.Active, st.Shadow)
	return err
}

func (p *Postgres) AppendAudit(ctx context.Context, ev *audit.Event) error {
	return p.tx(ctx, ev.Tenant, func(tx pgx.Tx) error {
		var prevSeq int64
		var prevHash string
		err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_events WHERE tenant=$1 ORDER BY seq DESC LIMIT 1`, ev.Tenant).
			Scan(&prevSeq, &prevHash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		link(ev, prevSeq, prevHash)
		subj, _ := json.Marshal(ev.Subject)
		res, _ := json.Marshal(ev.Resource)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events
			(tenant, seq, ts, caller, subject, action, resource, policy_version, allowed, reason,
			 shadow_version, shadow_allowed, shadow_diverged, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			ev.Tenant, ev.Seq, ev.TS, ev.Caller, subj, ev.Action, res, ev.PolicyVersion, ev.Allowed, ev.Reason,
			ev.ShadowVersion, ev.ShadowAllowed, ev.ShadowDiverge, ev.PrevHash, ev.Hash)
		return err
	})
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
