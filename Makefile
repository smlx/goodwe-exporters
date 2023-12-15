# local development targets

.PHONY: test
test: mod-tidy generate lint
	go test -v ./...

.PHONY: mod-tidy
mod-tidy:
	go mod tidy

.PHONY: generate
generate: mod-tidy
	go generate ./...

.PHONY: build
build:
	GOVERSION=$$(go version) goreleaser build  --clean --debug --snapshot

.PHONY: lint
lint:
	golangci-lint run
