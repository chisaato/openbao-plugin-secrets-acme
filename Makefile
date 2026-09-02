GO ?= go
PLUGIN_NAME = openbao-plugin-secrets-acme
VERSION ?= $(shell git describe --tags --always --dirty)

.PHONY: build test testacc vet fmt clean

build:
	$(GO) build -ldflags "-X main.pluginVersion=$(VERSION)" -o bin/$(PLUGIN_NAME) ./cmd/plugin

test:
	$(GO) test -race ./acme/...

testacc:
	$(GO) test -v ./test/...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin/
