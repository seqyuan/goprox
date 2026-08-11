# GoProx build helper.
# The version shown by `goprox --help` is taken from the nearest git tag so it
# always matches the tag (falls back to "dev" outside a git checkout).

VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)

.PHONY: build test vet fmt

build:
	go build -ldflags "-X main.version=$(VERSION)" -o goprox .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .
