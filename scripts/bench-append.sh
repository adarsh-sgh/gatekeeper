#!/usr/bin/env bash
# A/B of two commits on the Postgres append path. Default: e23b3b1
# (lock-select-insert transaction -> optimistic single INSERT). Builds
# gatekeeper at BEFORE and AFTER, then alternates them REPS times: Postgres
# store, 1 tenant, 64 gRPC clients, example policy, gkload for $DUR.
# Prints every run and the median. Needs `make up`.
#   BEFORE=e23b3b1 AFTER=HEAD ./scripts/bench-append.sh   # regression check
set -euo pipefail
cd "$(dirname "$0")/.."
DUR=${DUR:-10s}
REPS=${REPS:-5}
PG=${PG_DSN:-postgres://gatekeeper:gatekeeper@localhost:5432/gatekeeper?sslmode=disable}
HTTP=127.0.0.1:18091 GRPC=127.0.0.1:19096
tmp=$(mktemp -d)
trap 'git worktree remove --force "$tmp/before" 2>/dev/null; git worktree remove --force "$tmp/after" 2>/dev/null; rm -rf "$tmp"' EXIT
go build -o "$tmp/gkload" ./cmd/gkload
for side in "before:${BEFORE:-e23b3b1~1}" "after:${AFTER:-e23b3b1}"; do
	name=${side%%:*}
	git worktree add -q --detach "$tmp/$name" "${side#*:}"
	(cd "$tmp/$name" && go build -o "$tmp/gk-$name" ./cmd/gatekeeper)
done

run() {
	"$tmp/gk-$1" -dev-issuer -pg-dsn "$PG" -http "$HTTP" -grpc "$GRPC" -drain 0s >"$tmp/out" 2>/dev/null &
	local pid=$!
	until grep -q '^export TOKEN=' "$tmp/out" && curl -sf "http://$HTTP/healthz" >/dev/null; do sleep 0.1; done
	local tok
	tok=$(sed -n 's/^export TOKEN=//p' "$tmp/out")
	curl -sf -X PUT -H "Authorization: Bearer $tok" -d "$(jq -Rs '{rego:.}' policies/example.rego)" "http://$HTTP/v1/policies" >/dev/null
	"$tmp/gkload" -grpc "$GRPC" -token "$tok" -c 64 -d "$DUR" | sed -n 's/^throughput=\([0-9]*\).*p99=\([^ ]*\).*/\1 \2/p'
	kill "$pid"; wait "$pid" 2>/dev/null || true
}

for _ in $(seq "$REPS"); do
	for name in before after; do echo "$name $(run $name)"; done
done | tee "$tmp/runs"
for name in before after; do
	grep "^$name " "$tmp/runs" | sort -k2n | awk -v n="$name" '{v[NR]=$2; p[NR]=$3} END {m=int((NR+1)/2); printf "%s: median %.1fk appends/s (p99 %s) over %d runs\n", n, v[m]/1000, p[m], NR}'
done
