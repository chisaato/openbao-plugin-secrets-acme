GO ?= go
PLUGIN_NAME = openbao-plugin-secrets-acme

.PHONY: build test testacc vet fmt clean

build:
	$(GO) build -ldflags "-X github.com/chisaato/openbao-plugin-secrets-acme/acme.Version=v0.1.0" -o bin/$(PLUGIN_NAME) ./cmd/plugin

test:
	$(GO) test -race ./acme/...

testacc:
	# test/ 是独立 go module（隔离验收依赖），必须在其目录内运行。
	cd test && $(GO) test -v -timeout 15m ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin/
