#!/usr/bin/env bash
# Reproduces the README load-test table: one fresh server per run, the
# example policy installed for every tenant, gkload for $DUR per run. Each
# row runs $REPS times (interleaved with the other rows, so background load
# hits all rows alike) and the run with the median req/s is printed.
# Postgres rows need `make up`.
#   REPS=5 DUR=10s ONLY=postgres ./scripts/bench.sh
set -euo pipefail
cd "$(dirname "$0")/.."
DUR=${DUR:-10s}
REPS=${REPS:-1}
PG=${PG_DSN:-postgres://gatekeeper:gatekeeper@localhost:5432/gatekeeper?sslmode=disable}
HTTP=127.0.0.1:${BENCH_HTTP_PORT:-18090}
GRPC=127.0.0.1:${BENCH_GRPC_PORT:-19095}
RUN=$(date +%s)
go build -o bin/gatekeeper ./cmd/gatekeeper
go build -o bin/gkload ./cmd/gkload
REGO=$(jq -Rs '{rego:.}' policies/example.rego)

# row <label> <transport> <clients> <tenants> [server flags...]; ONLY=prefix filters labels.
# Prints label|transport|clients|tenants|req/s|p50|p99.
row() {
	[[ -n ${ONLY:-} && $1 != "$ONLY"* ]] && return
	local label=$1 transport=$2 clients=$3 tenants=$4
	shift 4
	bin/gatekeeper -dev-issuer -http "$HTTP" -grpc "$GRPC" -drain 0s "$@" >/dev/null 2>&1 &
	local pid=$!
	trap "kill $pid 2>/dev/null" EXIT
	until curl -sf "http://$HTTP/healthz" >/dev/null; do
		kill -0 "$pid" 2>/dev/null || { echo "gatekeeper exited (port in use?)" >&2; exit 1; }
		sleep 0.1
	done
	local toks=() t
	for i in $(seq "$tenants"); do
		t=$(curl -sf "http://$HTTP/dev/token?tenant=bench-$RUN-$RANDOM-$i")
		curl -sf -X PUT -H "Authorization: Bearer $t" -d "$REGO" "http://$HTTP/v1/policies" >/dev/null
		toks+=("$t")
	done
	local target=(-grpc "$GRPC")
	[ "$transport" = HTTP/1.1 ] && target=(-http "http://$HTTP")
	local out
	out=$(bin/gkload "${target[@]}" -token "$(IFS=,; echo "${toks[*]}")" -c "$clients" -d "$DUR")
	kill "$pid"; wait "$pid" 2>/dev/null || true
	echo "$out" | grep -q 'failed=0' || { echo "$out" >&2; exit 1; }
	echo "$out" | awk -v l="$label" -v tr="$transport" -v c="$clients" -v tn="$tenants" '
		/^throughput=/ { split($1,a,"="); split($3,b,"="); split($5,d,"="); print l "|" tr "|" c "|" tn "|" a[2] "|" b[2] "|" d[2] }'
}

rows() {
	row memory gRPC 16 1
	row memory gRPC 64 1
	row memory gRPC 256 1
	row memory HTTP/1.1 64 1
	row "memory, no token cache" gRPC 64 1 -token-cache 0
	row postgres gRPC 16 1 -pg-dsn "$PG"
	row postgres gRPC 64 1 -pg-dsn "$PG"
	row postgres gRPC 64 4 -pg-dsn "$PG"
	row postgres gRPC 64 16 -pg-dsn "$PG"
	row "postgres + outbox" gRPC 64 1 -pg-dsn "$PG" -outbox
	row "postgres + outbox" gRPC 64 16 -pg-dsn "$PG" -outbox
}

raw=$(for _ in $(seq "$REPS"); do rows; done)
echo "| store                  | transport | clients | tenants | req/s   | p50      | p99      |"
echo "|------------------------|-----------|--------:|--------:|--------:|---------:|---------:|"
echo "$raw" | awk -F'|' '
	{ k = $1 "|" $2 "|" $3 "|" $4; if (!(k in n)) order[++rows] = k; n[k]++; line[k, n[k]] = $0; rps[k, n[k]] = $5 }
	END {
		for (r = 1; r <= rows; r++) {
			k = order[r]
			for (i = 1; i <= n[k]; i++) idx[i] = i
			for (i = 1; i <= n[k]; i++) for (j = i + 1; j <= n[k]; j++)
				if (rps[k, idx[j]] < rps[k, idx[i]]) { t = idx[i]; idx[i] = idx[j]; idx[j] = t }
			split(line[k, idx[int((n[k] + 1) / 2)]], f, "|")
			printf "| %-22s | %-9s | %7s | %7s | %6.1fk | %8s | %8s |\n", f[1], f[2], f[3], f[4], f[5] / 1000, f[6], f[7]
		}
	}'
