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
	GOVERSION=$$(go version) \
						goreleaser build --clean --debug --single-target --snapshot

.PHONY: lint
lint:
	golangci-lint run --enable gocritic

.PHONY: fuzz
fuzz: mod-tidy generate
	go test -fuzz='^Fuzz' -fuzztime=10s -v ./internal/server

.PHONY: cover
cover: mod-tidy generate
	go test -v -covermode=atomic -coverprofile=cover.out -coverpkg=./... ./...
	go tool cover -html=cover.out
