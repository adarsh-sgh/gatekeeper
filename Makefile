.PHONY: run test test-integration proto up down certs lint build load

build:
	go build -o bin/gatekeeper ./cmd/gatekeeper

run: ## local dev: embedded JWT issuer, in-memory store, prints a token
	go run ./cmd/gatekeeper -dev-issuer

test:
	go test -race ./...

test-integration: ## needs `make up`
	PG_DSN=postgres://gatekeeper:gatekeeper@localhost:5432/gatekeeper?sslmode=disable \
		go test -race -tags integration ./internal/store/...

proto: export PATH := $(PATH):$(shell go env GOPATH)/bin
proto:
	protoc -I api --go_out=. --go_opt=module=github.com/adarsh-sgh/gatekeeper \
		--go-grpc_out=. --go-grpc_opt=module=github.com/adarsh-sgh/gatekeeper \
		api/gatekeeper/v1/gatekeeper.proto

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
