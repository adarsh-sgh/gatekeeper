#!/usr/bin/env bash
# Reproduces the README load-test table: one fresh server per row, the
# example policy installed for every tenant, gkload for $DUR per row.
# Postgres rows need `make up`. Prints markdown rows.
set -euo pipefail
cd "$(dirname "$0")/.."
DUR=${DUR:-10s}
PG=${PG_DSN:-postgres://gatekeeper:gatekeeper@localhost:5432/gatekeeper?sslmode=disable}
HTTP=127.0.0.1:${BENCH_HTTP_PORT:-18090}
GRPC=127.0.0.1:${BENCH_GRPC_PORT:-19095}
RUN=$(date +%s)
go build -o bin/gatekeeper ./cmd/gatekeeper
go build -o bin/gkload ./cmd/gkload
REGO=$(jq -Rs '{rego:.}' policies/example.rego)

# row <store> <transport> <clients> <tenants> [server flags...]
row() {
	local store=$1 transport=$2 clients=$3 tenants=$4
	shift 4
	bin/gatekeeper -dev-issuer -http "$HTTP" -grpc "$GRPC" -drain 0s "$@" >/dev/null 2>&1 &
	local pid=$!
	until curl -sf "http://$HTTP/healthz" >/dev/null; do sleep 0.1; done
	local toks=() t
	for i in $(seq "$tenants"); do
		t=$(curl -sf "http://$HTTP/dev/token?tenant=bench-$RUN-$store-$clients-$i")
		curl -sf -X PUT -H "Authorization: Bearer $t" -d "$REGO" "http://$HTTP/v1/policies" >/dev/null
		toks+=("$t")
	done
	local target=(-grpc "$GRPC")
	[ "$transport" = HTTP/1.1 ] && target=(-http "http://$HTTP")
	local out
	out=$(bin/gkload "${target[@]}" -token "$(IFS=,; echo "${toks[*]}")" -c "$clients" -d "$DUR")
	kill "$pid"; wait "$pid" 2>/dev/null || true
	echo "$out" | grep -q 'failed=0' || { echo "$out" >&2; exit 1; }
	echo "$out" | awk -v s="$store" -v tr="$transport" -v c="$clients" -v tn="$tenants" '
		/^throughput=/ { split($1,a,"="); split($3,b,"="); split($5,d,"=")
			printf "| %-15s | %-9s | %7s | %7s | %6.1fk | %8s | %8s |\n", s, tr, c, tn, a[2]/1000, b[2], d[2] }'
}

echo "| store           | transport | clients | tenants | req/s   | p50      | p99      |"
echo "|-----------------|-----------|--------:|--------:|--------:|---------:|---------:|"
row memory gRPC 16 1
row memory gRPC 64 1
row memory gRPC 256 1
row memory HTTP/1.1 64 1
row postgres gRPC 16 1 -pg-dsn "$PG"
row postgres gRPC 64 1 -pg-dsn "$PG"
row postgres gRPC 64 4 -pg-dsn "$PG"
row postgres gRPC 64 16 -pg-dsn "$PG"
row "postgres+outbox" gRPC 64 1 -pg-dsn "$PG" -outbox
row "postgres+outbox" gRPC 64 16 -pg-dsn "$PG" -outbox
