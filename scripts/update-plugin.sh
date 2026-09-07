#!/usr/bin/env bash
# 更新本地插件：构建插件 -> 计算 sha256 -> 拷贝至 data/plugins/ -> 更新 bao-config.hcl 中的 sha256sum -> 重启/reload 容器
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

PLUGIN_NAME="openbao-plugin-secrets-acme"
BIN_PATH="bin/$PLUGIN_NAME"
TARGET_DIR="data/plugins"
CONFIG_FILE="bao-config.hcl"

log() { printf '[update-plugin] %s\n' "$*"; }
die() { printf '[update-plugin] 错误：%s\n' "$*" >&2; exit 1; }

# 1. 确保已编译出二进制
if [[ ! -f "$BIN_PATH" ]]; then
  log "未检测到 $BIN_PATH，先执行构建..."
  just build-plugin
fi

# 2. 计算新编译产物的 SHA256
SHA256="$(sha256sum "$BIN_PATH" | awk '{print $1}')"
log "新插件 SHA256: $SHA256"

# 3. 拷贝到插件挂载目录
mkdir -p "$TARGET_DIR"
cp "$BIN_PATH" "$TARGET_DIR/"
log "已拷贝 $BIN_PATH -> $TARGET_DIR/"

# 4. 更新 bao-config.hcl 中的 sha256sum (如果文件存在)
if [[ -f "$CONFIG_FILE" ]]; then
  # 兼容 sed 替换 sha256sum = "..."
  sed -i -E "s|sha256sum[[:space:]]*=[[:space:]]*\"[a-f0-9]*\"|sha256sum = \"$SHA256\"|g" "$CONFIG_FILE"
  # 同时也处理未初始化的占位符 <sha256 of ...>
  sed -i -E "s|sha256sum[[:space:]]*=[[:space:]]*\"<[^>]*>\"|sha256sum = \"$SHA256\"|g" "$CONFIG_FILE"
  log "已同步更新 $CONFIG_FILE 中的 sha256sum"
fi

# 5. 如果 docker 容器正在运行，进行热重启或通过 openbao reload plugin
if command -v docker >/dev/null 2>&1 && docker compose ps --status running | grep -q "bao"; then
  log "检测到本地 OpenBao 容器运行中，重启容器应用新插件..."
  docker compose restart bao
  log "容器已重启，正在等待健康检查..."
  for _ in $(seq 1 30); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8200/v1/sys/health" || true)"
    if [[ "$code" == "200" || "$code" == "501" ]]; then
      log "OpenBao 服务就绪！"
      exit 0
    fi
    sleep 1
  done
  log "警告：OpenBao 30s 内未就绪，请检查 docker compose logs bao"
else
  log "本地 OpenBao 容器未运行。配置与二进制已准备好，启动时将直接生效。"
fi
