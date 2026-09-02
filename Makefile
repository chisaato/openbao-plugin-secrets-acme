GO ?= go
PLUGIN_NAME = openbao-plugin-secrets-acme
# 动态取最近 tag（release 由 tag 触发天然命中）；无 tag 回退 v0.1.0 保持可构建；
# ?= 允许外部覆盖（make VERSION=v0.2.0-rc1 release）。（I-3）
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.1.0)

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
	# 先清除上次运行的 SHA256SUMS：sha256sum * 会把旧清单卷入本次校验和，
	# 造成重跑污染。（L104）
	rm -f dist/SHA256SUMS
	cd dist && sha256sum * > SHA256SUMS
