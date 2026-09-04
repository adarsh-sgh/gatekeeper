# gatekeeper

Multi-tenant policy decision service in Go. Callers ask `Check(subject, action, resource)`;
gatekeeper evaluates the tenant's Rego policy with embedded OPA, writes every decision to a
hash-chained append-only audit log in Postgres, and returns allow/deny with a reason.
New policy versions can be rolled out in shadow mode: evaluated on live traffic, divergence
logged and counted, old decision served, until you promote them.

```
                    JWT (RS256, JWKS)            ┌──────────────┐
 client ──gRPC (mTLS opt.)──┐   ┌──interceptor──▶│   Service    │──eval──▶ OPA / Rego (cached per version)
 client ──HTTP/JSON─────────┴───┘                │ Check        │
                                                 │ PutPolicy    │──append─▶ audit chain  ─┐
      /metrics ◀── Prometheus                    │ Promote      │   (per-tenant sha256    │ Postgres
                                                 │ ListAudit    │    links, seq, prev)    │ (or memory)
                                                 │ VerifyChain  │──read───▶ policies ─────┘
                                                 └──────────────┘         + tenant rollout state
```

## Run

```sh
make run          # in-memory store, embedded JWT issuer; prints `export TOKEN=...`
make up           # Postgres via docker compose; then: go run ./cmd/gatekeeper -dev-issuer -pg-dsn "$PG_DSN"
make test         # unit + e2e, no docker needed
make test-integration   # Postgres conformance + tamper test (needs `make up`)
make certs        # self-signed CA/server/client certs; flags printed for mTLS on the gRPC port
```

```sh
H="Authorization: Bearer $TOKEN"
curl -X PUT -H "$H" -H "Idempotency-Key: v1" -d "$(jq -Rs '{rego:.}' policies/example.rego)" localhost:8080/v1/policies
curl -H "$H" -d '{"subject":{"id":"u1"},"action":"write","resource":{"type":"doc","attrs":{"owner":"u1"}}}' localhost:8080/v1/check
# {"allowed":true,"reason":"owner","policyVersion":"1","auditSeq":"1"}
curl -X PUT -H "$H" -d '{"rego":"...", "shadow":true}' localhost:8080/v1/policies   # v2 evaluated, not served
curl -H "$H" 'localhost:8080/v1/audit?limit=5'                                          # shadowDiverged per event
curl -X POST -H "$H" localhost:8080/v1/policies/2/promote
curl -H "$H" localhost:8080/v1/audit/verify        # {"ok":true,"eventsChecked":"N"}
```

The same five RPCs are served over gRPC (`api/gatekeeper/v1/gatekeeper.proto`); the HTTP
routes are a thin protojson mirror. Tokens need `tenant` and `sub` claims plus scopes
`policy:check`, `policy:write`, `audit:read`. In production point `-issuer`/`-jwks-url` at
your IdP; `-dev-issuer` embeds one for local use.

## Design decisions

- **Tenant comes from the token, never the body.** Every store call is keyed by
  `claims.Tenant`, so a caller cannot check or read another tenant's data even with a bug in
  request validation.
- **Fail closed, audit first.** A Check that cannot be evaluated or cannot be appended to
  the audit log returns an error, not a decision. An allow that was never logged does not exist.
- **Tamper evidence is per tenant and layered.** A Postgres trigger rejects UPDATE/DELETE on
  `audit_events`; independently, each event hashes its content plus the previous hash, so a
  privileged edit (trigger disabled) is still caught by `VerifyAuditChain` at the exact seq.
  The integration test does exactly that.
- **Shadow mode is the only rollout path that touches traffic.** A shadow version's errors
  are logged and counted but never surfaced, so a broken candidate cannot take down checks.
- **Appends are serialised per tenant, not globally**, via `pg_advisory_xact_lock(hashtext(tenant))`;
  tenants never contend with each other. Versions are immutable, so compiled Rego is cached
  by `(tenant, version)` with no invalidation.

## What I'd do next

- Bundle-style policy data (`data.*`) alongside the module, so policies can reference role
  hierarchies without inlining them.
- Periodic anchoring of each tenant's chain head to an external log (or signed by a KMS key)
  so the DB owner cannot rewrite the whole chain consistently.
- Streaming `WatchAudit` RPC and a small CLI for the shadow-diff review workflow.
