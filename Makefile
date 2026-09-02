GO ?= go
PLUGIN_NAME = openbao-plugin-secrets-acme
VERSION = v0.1.0

.PHONY: build test testacc vet fmt clean release

build:
	$(GO) build -ldflags "-X github.com/chisaato/openbao-plugin-secrets-acme/acme.Version=$(VERSION)" -o bin/$(PLUGIN_NAME) ./cmd/plugin

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
	rm -rf bin/ dist/

PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 linux/386 linux/riscv64

# release 交叉编译全部平台到 dist/ 并生成校验和；依赖 build 使 bin/ 内保留
# 本机（linux/amd64）二进制，供 Containerfile COPY 进 ghcr OCI 镜像。
# CGO_ENABLED=0：纯 Go 依赖，避免交叉编译时调用主机 gcc 汇编目标架构。
release: build
	mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -ldflags "-X github.com/chisaato/openbao-plugin-secrets-acme/acme.Version=$(VERSION)" \
			-o dist/$(PLUGIN_NAME)_$${os}_$${arch} ./cmd/plugin || exit 1; \
	done
	cd dist && sha256sum * > SHA256SUMS
