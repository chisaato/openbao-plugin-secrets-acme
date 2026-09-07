# Build stage
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /src

# 安装基础构建依赖
RUN apk add --no-cache ca-certificates git

# 预拉取依赖以复用缓存
COPY go.mod go.sum ./
RUN go mod download

# 拷贝源码
COPY . .

ARG TARGETOS TARGETARCH
ARG VERSION=v0.2.0

# 编译 plugin 与 cli
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X github.com/chisaato/openbao-plugin-secrets-acme/acme.Version=${VERSION}" \
    -o /out/openbao-plugin-secrets-acme ./cmd/plugin && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X github.com/chisaato/openbao-plugin-secrets-acme/acme.Version=${VERSION}" \
    -o /out/bao-acme ./cmd/bao-acme

# Runtime stage (Plugin OCI image)
FROM scratch

LABEL org.opencontainers.image.title="openbao-plugin-secrets-acme" \
      org.opencontainers.image.description="ACME / Let's Encrypt DNS-01 secrets engine plugin for OpenBao" \
      org.opencontainers.image.source="https://github.com/chisaato/openbao-plugin-secrets-acme"

# 拷贝 CA 根证书库，确保 ACME HTTPS 通信无障碍
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# 拷贝二进制
COPY --from=builder /out/openbao-plugin-secrets-acme /openbao-plugin-secrets-acme
COPY --from=builder /out/bao-acme /bao-acme

ENTRYPOINT ["/openbao-plugin-secrets-acme"]
