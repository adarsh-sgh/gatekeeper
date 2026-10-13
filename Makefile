.PHONY: run test test-integration test-acc proto up down certs lint build load bench e2e-envoy e2e-outbox

build:
	go build -o bin/gatekeeper ./cmd/gatekeeper

run: ## local dev: embedded JWT issuer, in-memory store, prints a token
	go run ./cmd/gatekeeper -dev-issuer

test:
	go test -race ./...

test-integration: ## needs `make up`
	PG_DSN=postgres://gatekeeper:gatekeeper@localhost:5432/gatekeeper?sslmode=disable \
		go test -race -tags integration ./internal/store/...

proto: ## regenerate api/ (messages, gRPC, grpc-gateway, OpenAPI) from the proto
	buf generate

test-acc: ## Terraform provider acceptance tests (needs terraform on PATH)
	TF_ACC=1 go test -count=1 ./internal/tfprovider/...

up: ## Postgres + Redpanda
	docker compose -f deploy/docker-compose.yml --profile stream up -d --wait postgres redpanda

down:
	docker compose -f deploy/docker-compose.yml --profile stream down -v

certs: ## self-signed CA + server + client certs for mTLS in ./certs
	./deploy/gen-certs.sh certs

lint:
	go vet ./...

load: ## needs a running server and TOKEN (from `make run`)
	go run ./cmd/gkload -grpc localhost:9090 -token "$(TOKEN)" -c 64 -d 10s

ENVOY_COMPOSE := deploy/envoy/docker-compose.yml
e2e-envoy: ## Envoy -> gatekeeper ext_authz, real containers
	docker compose -f $(ENVOY_COMPOSE) up -d --build
	ENVOY_COMPOSE_FILE=$(CURDIR)/$(ENVOY_COMPOSE) go test -count=1 -tags e2e -run TestEnvoyExtAuthz ./e2e/ ; \
		rc=$$?; docker compose -f $(ENVOY_COMPOSE) down; exit $$rc

e2e-outbox: ## outbox -> Redpanda -> idempotent consumer while relay/consumer are SIGKILLed (needs `make up`)
	go test -count=1 -v -tags e2e -run TestOutboxExactlyOnceUnderKills ./e2e/

bench: ## README load-test table (needs `make up` for the postgres rows)
	./scripts/bench.sh
