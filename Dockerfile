# 产物注入式镜像：二进制由外部交叉编译（just release / just build-image）放入 dist/，
# 本文件只做打包。这保证镜像内二进制与 GitHub Release 附件及 dist/SHA256SUMS
# 字节级一致——OpenBao plugin catalog 注册用的 sha256 即取自该清单。
#
# 多架构：buildx 对 platforms 列表逐平台渲染，ARG TARGETOS/TARGETARCH 命中
# dist/ 中对应命名（如 openbao-plugin-secrets-acme_linux_arm64）的产物。

# CA 根证书与目标架构无关，固定在构建机平台提取，避免多架构构建时走 QEMU。
FROM --platform=$BUILDPLATFORM alpine:3 AS certs

RUN apk add --no-cache ca-certificates

FROM scratch

LABEL org.opencontainers.image.title="openbao-plugin-secrets-acme" \
      org.opencontainers.image.description="ACME / Let's Encrypt DNS-01 secrets engine plugin for OpenBao" \
      org.opencontainers.image.source="https://github.com/chisaato/openbao-plugin-secrets-acme"

ARG TARGETOS TARGETARCH

# 拷贝 CA 根证书库，确保 ACME HTTPS 通信无障碍
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# 拷贝外部构建产物
COPY dist/openbao-plugin-secrets-acme_${TARGETOS}_${TARGETARCH} /openbao-plugin-secrets-acme
COPY dist/bao-acme_${TARGETOS}_${TARGETARCH} /bao-acme

ENTRYPOINT ["/openbao-plugin-secrets-acme"]
