# OpenBao ACME 插件构建入口（原 Makefile 的等价迁移）
set shell := ["bash", "-cu"]

plugin_name := "openbao-plugin-secrets-acme"
# 动态取最近 tag（release 由 tag 触发天然命中）；无 tag 回退 v0.1.0 保持可构建；
# 命令行可覆盖（just version=v0.2.0-rc1 release）。
version := `git describe --tags --abbrev=0 2>/dev/null || echo v0.1.0`
ldflags := "-X github.com/chisaato/openbao-plugin-secrets-acme/acme.Version=" + version

# 交叉编译目标平台
platforms := "linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 linux/386 linux/riscv64"

# 默认目标：构建
default: build

# 构建 bin/openbao-plugin-secrets-acme（ldflags 注入 acme.Version）以及 CLI bin/bao-acme
build: build-plugin build-cli

build-plugin:
    go build -ldflags '{{ ldflags }}' -o bin/{{ plugin_name }} ./cmd/plugin

build-cli:
    go build -ldflags '{{ ldflags }}' -o bin/bao-acme ./cmd/bao-acme

# 单测（-race），离线
test:
    go test -race ./acme/... ./pkg/... ./cmd/...

# 验收测试（test/ 独立 module，需本机 pebble + challtestsrv + bao；缺失则自动 Skip）
testacc:
    cd test && go test -v -timeout 15m ./...

# 初始化本地 bao（起容器 + operator init + 凭据存 data/credentials.json + 回填 token）；
# 传 --reset 彻底重置（销毁 data/data 重新 init）。详见 docs/local-testing.md。
init flag="":
    ./scripts/init-bao.sh {{ flag }}

vet:
    go vet ./...

fmt:
    go fmt ./...

clean:
    rm -rf bin/ dist/

# 交叉编译全部平台到 dist/ 并生成 SHA256SUMS；依赖 build 使 bin/ 内保留本机
# （linux/amd64）二进制，供 Containerfile COPY 进 ghcr OCI 镜像。
# CGO_ENABLED=0：纯 Go 依赖，避免交叉编译时调用主机 gcc 汇编目标架构。
release: build
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p dist
    for p in {{ platforms }}; do
        os="${p%/*}"; arch="${p#*/}"
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
            go build -ldflags '{{ ldflags }}' \
            -o "dist/{{ plugin_name }}_${os}_${arch}" ./cmd/plugin
    done
    # 先清除上次运行的 SHA256SUMS：sha256sum * 会把旧清单卷入本次校验和，造成重跑污染。
    rm -f dist/SHA256SUMS
    (cd dist && sha256sum * > SHA256SUMS)
