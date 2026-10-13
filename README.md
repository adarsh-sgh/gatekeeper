# gatekeeper

Multi-tenant policy decision service in Go. Callers ask `Check(subject, action, resource)`;
gatekeeper evaluates the tenant's Rego policy with embedded OPA, writes every decision to a
hash-chained append-only audit log in Postgres, and returns allow/deny with a reason.
New policy versions can be rolled out in shadow mode: evaluated on live traffic, divergence
logged and counted, old decision served, until you promote them.

Around that core:

- **One Protobuf spec** (`api/gatekeeper/v1/gatekeeper.proto`) generates the gRPC server,
  the HTTP/JSON API (grpc-gateway, from `google.api.http` annotations), an OpenAPI document,
  and the Go SDK client.
- **Envoy external authorization**: gatekeeper implements Envoy's `ext_authz` gRPC API, so
  any Envoy-fronted service gets per-tenant Rego decisions and audit with no code change.
- **`gkctl`**, a decK-style Cobra CLI: declarative YAML of tenants and policies, `diff`
  (drift detection, exit 2), `sync`, `dump`.
- **A Terraform provider** (terraform-plugin-framework) for tenants and policies, on the same SDK.
- **Transactional outbox**: audit events are relayed to Kafka (Redpanda in compose) and
  applied by an idempotent consumer; an e2e test SIGKILLs relay and consumer mid-stream and
  proves the effect is exactly once.

```
                          JWT (RS256, JWKS)                ┌───────────────┐
 client ──gRPC (mTLS opt.)─────────┐   ┌──interceptor─────▶│   Service     │──eval──▶ OPA / Rego (cached per version)
 client ──HTTP/JSON (grpc-gateway)─┴───┘                   │ Check         │
 Envoy ──ext_authz gRPC (end-user token in headers)───────▶│ policies      │──append─▶ audit chain ──┐ same INSERT ┐
 gkctl / Terraform ──Go SDK (generated gRPC client)───────▶│ tenants       │                         │             ▼
      /metrics ◀── Prometheus                              │ audit, verify │                Postgres │      audit_outbox
                                                           └───────────────┘                         │             │
                         gkconsumer ◀── Kafka topic (key = tenant) ◀── gkrelay (leader-locked) ◀─────┴─────────────┘
                   (dedup ledger + projection, one tx)
```

## Run

```sh
make run          # in-memory store, embedded JWT issuer; prints `export TOKEN=...` (all scopes)
make up           # Postgres + Redpanda via docker compose
make test         # unit + in-process e2e (gRPC, HTTP, ext_authz, gkctl, SIGTERM drain), no docker
make test-integration   # Postgres conformance, tamper, cross-instance append, outbox atomicity (needs `make up`)
make test-acc     # Terraform provider acceptance tests (needs terraform on PATH)
make e2e-envoy    # real Envoy + gatekeeper containers: allow, deny, 401, fail closed
make e2e-outbox   # relay/consumer SIGKILLed under load, exactly-once effect (needs `make up`)
make proto        # buf generate: messages, gRPC, grpc-gateway, OpenAPI
make bench        # the load-test table below
make certs        # self-signed CA/server/client certs for mTLS on the gRPC port
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

Tokens need `tenant` and `sub` claims plus scopes `policy:check`, `policy:write`,
`audit:read`; `tenants:admin` manages the tenant registry and other tenants' policies. In
production point `-issuer`/`-jwks-url` at your IdP; `-dev-issuer` embeds one for local use.

### Envoy

`deploy/envoy/envoy.yaml` puts the `ext_authz` HTTP filter (gRPC, `failure_mode_allow:
false`, `status_on_error: 503`) in front of a stand-in upstream. Gatekeeper verifies the
end user's bearer token from the forwarded headers and maps the request to a Check:
subject = `sub` + `roles`, tenant = `tenant` claim, action = `read` for GET/HEAD/OPTIONS and
`write` otherwise, resource = `{type: "http", id: <path without query>, attrs: {method, host, path}}`
(`policies/http.rego` is an example). Allowed requests reach upstream with
`x-gatekeeper-tenant`/`x-gatekeeper-subject` set (client copies overwritten) and the client
gets `x-gatekeeper-audit-seq`; denials are 403 with the reason, missing/invalid tokens 401.
`e2e/envoy_test.go` drives the containers, checks that a spoofed `x-gatekeeper-subject` from
the client never reaches upstream, that the audit log holds exactly the proxied decisions,
then stops gatekeeper and expects Envoy to fail closed with 503.

### gkctl and Terraform

```yaml
# examples/gkctl/gatekeeper.yaml; policy paths are relative to the file
tenants:
  - name: acme
    display_name: Acme Corp
    policy: policies/acme.rego        # active slot
    shadow: policies/acme-next.rego   # optional shadow slot
```

```sh
export GATEKEEPER_ADDR=localhost:9090 GATEKEEPER_TOKEN=$TOKEN
gkctl diff -f gatekeeper.yaml   # +/~/^/- per change, unified Rego diff; exit 2 on drift
gkctl sync -f gatekeeper.yaml   # creates, updates, deletes tenants missing from the file
gkctl dump --dir out > out/gatekeeper.yaml   # round-trips: diff of a dump is empty
```

`examples/terraform/main.tf` manages the same objects: `gatekeeper_tenant` (name,
display_name, disabled) and `gatekeeper_policy` (tenant, rego, shadow; computed version).
Both import (`acme`, `acme/active`).

## Design decisions

- **Tenant comes from the token, never the body.** Every store call is keyed by
  `claims.Tenant`, so a caller cannot check or read another tenant's data even with a bug in
  request validation. The one exception is the `tenant` field on policy RPCs, honoured only
  with `tenants:admin`, which is what gkctl and Terraform use.
- **Fail closed, audit first.** A Check that cannot be evaluated or cannot be appended to
  the audit log returns an error, not a decision. An allow that was never logged does not
  exist. The same holds at the edge: ext_authz errors become Envoy 503s, never allows.
  Unsetting a tenant's policy, disabling the tenant, or deleting it all make its checks deny.
- **The proto is the API.** HTTP routes are grpc-gateway's, served in process
  (`RegisterGatekeeperHandlerServer`, no loopback gRPC hop) behind the same auth, limiter and
  access log as gRPC, so adding an RPC adds its REST route, OpenAPI entry and SDK method in
  one `buf generate`. CI fails if generated code drifts from the proto.
- **ext_authz reuses the Check path, not a copy of it.** `decide()` is shared, so Envoy
  decisions get the same shadow evaluation, metrics and audit chain. The gRPC auth
  interceptor skips the ext_authz method because Envoy calls without a token of its own;
  the decision is about the forwarded end-user token, which the adapter verifies itself.
- **Declarative tools need idempotent, independent pieces.** Policy versions are immutable,
  so `sync` and Terraform express "change the Rego" as a new version; the active and shadow
  slots are independent, so they apply in any order. `gkctl` detects a promotion (the file's
  active Rego equals the server's shadow) and calls `PromotePolicy` instead of minting a
  version, keeping the version whose divergence was observed. Terraform's Read loads
  whatever version occupies the slot, so an out-of-band change shows up as a Rego diff.
- **Tamper evidence is per tenant and layered.** A Postgres trigger rejects UPDATE/DELETE on
  `audit_events`; independently, each event hashes its content plus the previous hash, so a
  privileged edit (trigger disabled) is still caught by `VerifyAuditChain` at the exact seq.
- **Appends are serialised per tenant, not globally.** Each instance caches the chain head
  per tenant and appends with one `INSERT`; the `(tenant, seq)` primary key arbitrates races
  between instances (lose → reload head, retry), and after three losses the append takes
  `pg_advisory_xact_lock(hashtext(tenant))` in a transaction. The fast path only inserts if
  it can `pg_try_advisory_xact_lock` the same key, so a locked writer is never overtaken.
  This replaced a lock-select-insert transaction (5 round trips; commit e23b3b1), which on the
  Sep 2026 run took a single tenant from ~1.1k to ~4k appends/s.
- **Outbox in the same statement, not just the same transaction.** With `-outbox` the audit
  insert becomes `WITH ev AS (INSERT INTO audit_events … RETURNING tenant) INSERT INTO
  audit_outbox … FROM ev`: one round trip, atomic, and the outbox row exists iff the audit
  row does, including under the PK-race retries above.
- **At-least-once relay, exactly-once effect.** `gkrelay` holds a session advisory lock
  (one leader; standbys take over when its connection drops), reads outbox rows in id order,
  produces them keyed by tenant with acks=all, and deletes them only after the ack. A crash
  between ack and delete republishes the batch. `gkconsumer` commits offsets manually after
  applying each batch in a single statement that inserts event ids into a ledger
  (`ON CONFLICT DO NOTHING`, plus `DISTINCT ON` for duplicates inside one batch) and bumps
  per-tenant counters only for ids it had not seen. It uses static group membership, so a
  restarted consumer reclaims its partitions without waiting out the session timeout.
- **Verified tokens are cached** (sha256(token) → claims, ≤ `-token-cache`, default 60s,
  bounded to 10k entries). pprof showed RS256 verification as the largest per-request CPU
  cost after syscalls; `-token-cache 0` turns it off for the A/B row below.

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
  `Retry-After` (Envoy clients get the 429 too), counted in `gatekeeper_ratelimited_total{tenant}`.
- **Request ids and access logs.** `x-request-id` is honoured from the caller (HTTP header or
  gRPC metadata) or generated, echoed back, and stamped on the JSON access-log line together
  with tenant, method, status code and duration. `-pprof` mounts `net/http/pprof`.
- **Metrics.** Besides decisions, shadow divergence and Rego latency:
  `gatekeeper_request_seconds{method,code}`, `gatekeeper_inflight_requests`,
  `gatekeeper_ratelimited_total{tenant}`.
- **Outbox.** Run two or more `gkrelay`s for availability (one leads). `audit_outbox` depth is
  the relay lag; it drains to zero when the relay keeps up.

## Load test

`cmd/gkload` runs N concurrent clients against Check over HTTP or gRPC and reports
throughput and latency percentiles; `scripts/bench.sh` (`make bench`) produces this table:
a fresh server per run, the example policy installed for every tenant, each row run 5
times for 10s interleaved with the other rows, median run shown. Every Check evaluates Rego
and appends to the audit chain. Setup: one Apple M5 laptop (10 cores, macOS) running client,
server and Postgres 16 (Docker) together, with unrelated workloads on the machine (load
average 5-12), so the numbers bound the service's own overhead rather than model production.
Memory rows: Oct 14 2026 05:00-05:10 IST; Postgres rows: 05:14-05:20 IST.

| store                  | transport | clients | tenants | req/s  | p50     | p99     |
|------------------------|-----------|--------:|--------:|-------:|--------:|--------:|
| memory                 | gRPC      |      16 |       1 |  61.0k |  0.21ms |  0.74ms |
| memory                 | gRPC      |      64 |       1 |  83.7k |  0.67ms |  2.2ms  |
| memory                 | gRPC      |     256 |       1 |  89.7k |  2.5ms  |  8.0ms  |
| memory                 | HTTP/1.1  |      64 |       1 |  69.0k |  0.58ms |  5.1ms  |
| memory, no token cache | gRPC      |      64 |       1 |  60.7k |  0.94ms |  3.0ms  |
| postgres               | gRPC      |      16 |       1 |   3.9k |  3.8ms  |  7.6ms  |
| postgres               | gRPC      |      64 |       1 |   3.9k |  15ms   |  30ms   |
| postgres               | gRPC      |      64 |       4 |   6.6k |  9.4ms  |  15ms   |
| postgres               | gRPC      |      64 |      16 |   8.2k |  7.5ms  |  12ms   |
| postgres + outbox      | gRPC      |      64 |       1 |   3.6k |  16ms   |  36ms   |
| postgres + outbox      | gRPC      |      64 |      16 |   8.1k |  7.8ms  |  11ms   |

- With Postgres a single tenant is bound by its serialised chain (one insert round trip at
  a time); throughput grows with the number of tenants, which is the point of per-tenant
  rather than global ordering.
- The token cache is worth +38% at 64 gRPC clients (60.7k → 83.7k).
- The outbox costs one extra row per decision inside the same statement: 3.9k → 3.6k for
  one tenant, 8.2k → 8.1k for 16. An earlier session the same morning, under heavier
  background load, measured the Postgres rows lower (3.3k / 3.3k / 5.8k / 7.6k, outbox
  3.1k / 6.9k); session-to-session variance on this machine is larger than the outbox cost
  at 16 tenants.
- The HTTP row goes through the generated grpc-gateway mux, in process.
- Append-path A/B (`scripts/bench-append.sh`, 5 alternating runs each, Postgres, 1 tenant,
  64 clients): commit e23b3b1 took appends from 1.9k to 4.0k/s (p99 50ms → 22ms) versus
  its parent; e23b3b1 vs today's HEAD is 4.1k vs 4.0k, i.e. the new features did not slow
  the append path.
- With `-rate 20000 -burst 1000` at 64 clients the limiter admitted 20.0k req/s and rejected
  the rest at 80k req/s offered (September run).

## Outbox kill test

`e2e/outbox_test.go` (CI job `integration`) starts gatekeeper with `-outbox` on Postgres,
fires 20,000 Checks over HTTP across 4 tenants (half allowed, half denied) and, while they
run, supervises `gkrelay` and `gkconsumer`: each is restarted whenever it exits and SIGKILLed
every 150-500 ms at random. The first run of each also exits at its duplicate-producing
point (relay: after the broker ack, before deleting rows; consumer: after the DB apply,
before committing offsets). Then it waits for the pair to drain and checks the projection
against the audit log itself.

| run                                   | events | relay SIGKILLs | consumer SIGKILLs | duplicate records on topic | redelivered records skipped | projection vs audit log |
|---------------------------------------|-------:|---------------:|------------------:|---------------------------:|----------------------------:|------------------------|
| GitHub Actions `ubuntu-latest`, CI    | 20,000 | 13             | 11                | 79                         | ≥ 2,260                     | equal (0 off)          |
| Apple M5 laptop, Postgres/Redpanda in Docker | 20,000 | 22      | 19                | 500                        | ≥ 1,171                     | equal (0 off)          |

Both runs also had the one injected crash per process. "Duplicate records" is topic
records minus events (relay republished after an ack); "skipped" is what the consumer
saw again and did not apply (relay duplicates plus redeliveries after a crash before the
offset commit), counted from its logs, so a lower bound. The test fails unless the ledger
holds exactly 20,000 ids, every per-tenant allow/deny count equals `audit_events`,
the outbox drained, and duplicates were actually delivered.

## Gaps

- The Envoy e2e's upstream is a `direct_response` route that echoes the identity headers
  it received; a real upstream service is not part of the stack.
- ext_authz trusts the network path from Envoy (no mTLS or caller token on that hop in the
  demo config); anyone who can reach the gRPC port can ask for decisions about tokens they hold.
- Outbox ordering is per tenant only while a single relay leads; the consumer's projection
  is commutative, so it does not depend on order, but a consumer that did would need the
  chain seq to reorder. The dedup ledger grows without bound (no TTL/compaction yet).
- The consumer stops on an undecodable message instead of dead-lettering it.
- `gkctl sync` deletes every registered tenant missing from the file, with no `--select-tag`
  scoping as decK has; there is no dry-run beyond `diff`.
- Terraform: no data sources, no provider registry release, acceptance tests run against an
  in-process server (memory store), not a deployed one.
- Load numbers are one laptop with client, server and Postgres co-located; see the caveats above.

## What I'd do next

- Bundle-style policy data (`data.*`) alongside the module, so policies can reference role
  hierarchies without inlining them.
- Periodic anchoring of each tenant's chain head to an external log (or signed by a KMS key)
  so the DB owner cannot rewrite the whole chain consistently.
- Batch audit appends (group commits per tenant) to lift the single-tenant ceiling.
- Ledger compaction keyed by the chain seq (a consumer only needs the high-water seq per
  tenant once order is guaranteed).
