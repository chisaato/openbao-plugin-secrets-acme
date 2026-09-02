GO ?= go
PLUGIN_NAME = openbao-plugin-secrets-acme

.PHONY: build test testacc vet fmt clean

build:
	$(GO) build -ldflags "-X github.com/chisaato/openbao-plugin-secrets-acme/acme.Version=v0.1.0" -o bin/$(PLUGIN_NAME) ./cmd/plugin

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
