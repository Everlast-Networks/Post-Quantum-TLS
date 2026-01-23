.PHONY: build test lint

build:
	go build ./cmd/client
	go build ./cmd/server
	go build ./cmd/keyutil

test:
	go test ./...

lint:
	golangci-lint run ./...
