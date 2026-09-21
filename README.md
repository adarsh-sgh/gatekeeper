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
make test         # unit + e2e (incl. SIGTERM drain), no docker needed
make test-integration   # Postgres conformance, tamper and cross-instance append tests (needs `make up`)
make certs        # self-signed CA/server/client certs; flags printed for mTLS on the gRPC port
make load         # gkload: 64 clients for 10s against the local server, prints throughput and p50/p90/p99
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
- **Appends are serialised per tenant, not globally.** Each instance caches the chain head
  per tenant and appends with one `INSERT`; the `(tenant, seq)` primary key arbitrates races
  between instances (lose → reload head, retry), and after three losses the append takes
  `pg_advisory_xact_lock(hashtext(tenant))` in a transaction. The fast path only inserts if
  it can `pg_try_advisory_xact_lock` the same key, so a locked writer is never overtaken.
  This replaced a lock-select-insert transaction (5 round trips) and took a single tenant
  from ~1.1k to ~4k appends/s on the setup below. Versions are immutable, so compiled Rego
  is cached by `(tenant, version)` with no invalidation.
- **Verified tokens are cached** (sha256(token) → claims, ≤ 60s, bounded to 10k entries).
  pprof showed RS256 verification as the largest per-request CPU cost after syscalls;
  caching it raised gRPC throughput at 64 clients from ~45k to ~62k req/s.

## Operating it

- **Readiness vs liveness.** `GET /healthz` says the process is up. `GET /readyz` and
  `grpc.health.v1` say "route traffic here": they fail while the store does not answer or
  the process is draining. `deploy/k8s.yaml` wires both probes.
- **Graceful drain.** On SIGTERM readiness flips to failing on both transports first, the
  listeners stay open for `-drain` (default 5s) so load balancers and kubelet stop sending
  new connections, then listeners close and in-flight requests get `-shutdown-timeout`
  (default 10s) before gRPC streams are killed. `TestSIGTERMDrainsBeforeStopping` sends a
  real SIGTERM and checks each step.
- **Per-tenant rate limiting.** `-rate N -burst B` gives every tenant its own token bucket
  (`internal/ratelimit`); over-limit calls get `429` / `RESOURCE_EXHAUSTED` with a
  `Retry-After`, counted in `gatekeeper_ratelimited_total{tenant}`. Idle buckets are swept.
- **Request ids and access logs.** `x-request-id` is honoured from the caller (HTTP header or
  gRPC metadata) or generated, echoed back, and stamped on the JSON access-log line together
  with tenant, method, status code and duration. `-pprof` mounts `net/http/pprof`.
- **Metrics.** Besides decisions, shadow divergence and Rego latency:
  `gatekeeper_request_seconds{method,code}`, `gatekeeper_inflight_requests`,
  `gatekeeper_ratelimited_total{tenant}`.

## Load test

`cmd/gkload` runs N concurrent clients against `/v1/check` over HTTP or gRPC and reports
throughput and latency percentiles. Numbers below are one laptop (Apple M5, 10 cores) running
server, client and Postgres 16 in Docker together, 10s runs, so they bound the service's own
overhead rather than model production. Every Check evaluates Rego and appends to the audit chain.

| store    | transport | clients | tenants | req/s  | p50     | p99     |
|----------|-----------|--------:|--------:|-------:|--------:|--------:|
| memory   | gRPC      | 16      | 1       | 46k    | 0.27ms  | 1.4ms   |
| memory   | gRPC      | 64      | 1       | 64k    | 0.81ms  | 3.8ms   |
| memory   | gRPC      | 256     | 1       | 63k    | 3.4ms   | 14ms    |
| memory   | HTTP/1.1  | 64      | 1       | 62k    | 0.63ms  | 6.5ms   |
| postgres | gRPC      | 16      | 1       | 4.0k   | 3.8ms   | 7.1ms   |
| postgres | gRPC      | 64      | 1       | 4.0k   | 15ms    | 22ms    |
| postgres | gRPC      | 64      | 4       | 6.6k   | 9.5ms   | 13ms    |
| postgres | gRPC      | 64      | 16      | 8.4k   | 7.4ms   | 10ms    |

With Postgres a single tenant is bound by its serialised chain (one insert round trip at a
time); throughput grows with the number of tenants, which is the point of per-tenant rather
than global ordering. With `-rate 20000 -burst 1000` at 64 clients the limiter admitted
20.0k req/s and rejected the rest at 80k req/s offered.

## What I'd do next

- Bundle-style policy data (`data.*`) alongside the module, so policies can reference role
  hierarchies without inlining them.
- Periodic anchoring of each tenant's chain head to an external log (or signed by a KMS key)
  so the DB owner cannot rewrite the whole chain consistently.
- Streaming `WatchAudit` RPC and a small CLI for the shadow-diff review workflow.
- Batch audit appends (group commits per tenant) to lift the single-tenant ceiling.
