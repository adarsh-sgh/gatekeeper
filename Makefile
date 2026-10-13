.PHONY: run test test-integration proto up down certs lint build load e2e-envoy

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

up:
	docker compose -f deploy/docker-compose.yml up -d --wait

down:
	docker compose -f deploy/docker-compose.yml down -v

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
