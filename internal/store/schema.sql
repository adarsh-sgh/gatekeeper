CREATE TABLE IF NOT EXISTS policies (
    tenant          text        NOT NULL,
    version         bigint      NOT NULL,
    rego            text        NOT NULL,
    idempotency_key text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, version),
    UNIQUE (tenant, idempotency_key)
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant         text PRIMARY KEY,
    active_version bigint NOT NULL DEFAULT 0,
    shadow_version bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_events (
    tenant          text        NOT NULL,
    seq             bigint      NOT NULL,
    ts              timestamptz NOT NULL,
    caller          text        NOT NULL,
    subject         jsonb       NOT NULL,
    action          text        NOT NULL,
    resource        jsonb       NOT NULL,
    policy_version  bigint      NOT NULL,
    allowed         boolean     NOT NULL,
    reason          text        NOT NULL,
    shadow_version  bigint      NOT NULL,
    shadow_allowed  boolean     NOT NULL,
    shadow_diverged boolean     NOT NULL,
    prev_hash       text        NOT NULL,
    hash            text        NOT NULL,
    PRIMARY KEY (tenant, seq)
);

-- The audit log is append-only at the database level, not just by convention.
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_no_modify ON audit_events;
CREATE TRIGGER audit_events_no_modify
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
