#!/usr/bin/env bash
# OpenBao 本地环境自动初始化（配合 compose.yaml / bao-config.hcl，用法见 docs/local-testing.md）。
#
# 功能：
#   1. 确保 static seal 的 unseal.key 存在（bao 启动硬要求，不会自动生成）
#   2. docker compose up 并等待服务就绪
#   3. 未初始化时执行 bao operator init，凭据保存到 data/credentials.json（0600）
#   4. 把 root token 回填到 bao-config.hcl 的插件 BAO_TOKEN（本地测试环境）
#   5. 已初始化时校验已保存的 root token 是否仍然有效
#
# 用法：
#   scripts/init-bao.sh            # 常规初始化（已初始化则只校验）
#   scripts/init-bao.sh --reset    # 彻底重置：清空 data/data 重新 init（销毁全部数据）
#
# 坑位说明（实测踩过）：
#   - static seal 下 init 不能带 -key-shares/-key-threshold（报 parameters not applicable）
#   - 容器内 bao CLI 默认 BAO_ADDR=https://...，本地 listener 是 HTTP，必须显式传 http://
#   - data/data 属主是容器内 root（compose user: "0:0"），清理/写入 unseal.key 需要 sudo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

ADDR="http://127.0.0.1:8200"
STORE_DIR="data/data"
UNSEAL_KEY_FILE="$STORE_DIR/unseal.key"
CRED_FILE="data/credentials.json"
CONFIG_FILE="bao-config.hcl"

log() { printf '[init-bao] %s\n' "$*"; }
die() { printf '[init-bao] 错误：%s\n' "$*" >&2; exit 1; }

# ---- 依赖检查 ----------------------------------------------------------------
for cmd in docker curl jq sudo; do
  command -v "$cmd" >/dev/null || die "缺少依赖：$cmd"
done
docker compose version >/dev/null 2>&1 || die "docker compose v2 不可用"
[[ -f "$CONFIG_FILE" ]] || die "缺少 $CONFIG_FILE（先执行：cp bao-config.hcl.example bao-config.hcl）"

# ---- 等待服务就绪 -------------------------------------------------------------
# /v1/sys/health：200=就绪，501=已启动未初始化，503=sealed；其余/无响应=未就绪
wait_healthy() {
  for _ in $(seq 1 30); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$ADDR/v1/sys/health" || true)"
    case "$code" in
      200) echo "ready" ; return 0 ;;
      501) echo "uninitialized" ; return 0 ;;
    esac
    sleep 1
  done
  die "服务 30s 内未就绪（docker compose logs bao 查看原因）"
}

# ---- 生成 static seal key（sudo：data/data 属主为 root）----------------------
ensure_unseal_key() {
  [[ -f "$UNSEAL_KEY_FILE" ]] && return 0
  log "生成新的 static seal key → $UNSEAL_KEY_FILE"
  sudo -n sh -c "mkdir -p '$STORE_DIR' && head -c 32 /dev/urandom > '$UNSEAL_KEY_FILE' \
    && chown 0:0 '$UNSEAL_KEY_FILE' && chmod 640 '$UNSEAL_KEY_FILE'"
}

# ---- 重置：销毁 raft 数据重来 -------------------------------------------------
if [[ "${1:-}" == "--reset" ]]; then
  log "--reset：停止容器并清空 $STORE_DIR（数据不可恢复）"
  docker compose down
  sudo -n rm -rf "$STORE_DIR"
fi

ensure_unseal_key
log "启动容器"
docker compose up -d
state="$(wait_healthy)"

# ---- 分支一：未初始化 → init 并保存凭据 ---------------------------------------
if [[ "$state" == "uninitialized" ]]; then
  log "集群未初始化，执行 bao operator init（static seal 不支持 key 分片参数）"
  init_json="$(docker compose exec -T -e "BAO_ADDR=$ADDR" bao bao operator init -format=json)"
  [[ -n "$init_json" ]] || die "init 输出为空"

  token="$(printf '%s' "$init_json" | jq -r '.root_token // empty')"
  [[ -n "$token" ]] || die "init 输出中没有 root_token"

  # 附加 static seal key 备份与元信息后落盘（0600；data/ 整体已被 gitignore）
  seal_b64="$(sudo -n base64 -w0 "$UNSEAL_KEY_FILE")"
  printf '%s' "$init_json" | jq \
    --arg seal "$seal_b64" \
    --arg addr "$ADDR" \
    --arg ts "$(date -Iseconds)" \
    '. + {static_seal_key_b64: $seal, bao_addr: $addr, initialized_at: $ts}' > "$CRED_FILE"
  chmod 600 "$CRED_FILE"
  log "凭据已保存 → $CRED_FILE"

  # 回填 bao-config.hcl 的插件 BAO_TOKEN（换行/逗号风格都兼容）
  if grep -q 'BAO_TOKEN=' "$CONFIG_FILE"; then
    sed -i -E "s|BAO_TOKEN=[^\"']*|BAO_TOKEN=$token|g" "$CONFIG_FILE"
    log "root token 已回填 $CONFIG_FILE，重启容器使其生效"
    docker compose restart bao
    wait_healthy >/dev/null
  else
    log "警告：$CONFIG_FILE 中没有 BAO_TOKEN 行，跳过回填"
  fi
else
  # ---- 分支二：已初始化 → 校验已保存的 token ---------------------------------
  [[ -f "$CRED_FILE" ]] || die "集群已初始化但 $CRED_FILE 不存在，无法取回 root token；如可弃数据请用 --reset"
  token="$(jq -r '.root_token // empty' "$CRED_FILE")"
  [[ -n "$token" ]] || die "$CRED_FILE 中没有 root_token"
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "X-Vault-Token: $token" "$ADDR/v1/auth/token/lookup-self")"
  [[ "$code" == "200" ]] || die "已保存的 root token 已失效（HTTP $code）；如可弃数据请用 --reset"
  log "集群已初始化，root token 校验通过"
fi

# ---- 摘要 ---------------------------------------------------------------------
log "完成：Web UI / CLI 均使用 $ADDR"
log "root token: $token"
log "凭据文件:   $CRED_FILE（含 recovery keys 与 static seal key 备份）"
