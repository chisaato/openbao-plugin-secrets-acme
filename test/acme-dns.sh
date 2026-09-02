#!/usr/bin/env bash
# lego v5 exec provider 适配脚本：真实执行 DNS TXT 写/清（面向 pebble challtestsrv）。
# lego v5 exec 以 argv 调用（非 RAW 模式）：本脚本 present|cleanup <fqdn> <value>；
# fqdn 形如 _acme-challenge.example.com.（带尾点）。
# challtestsrv 管理 API 按项目约定为 8056（Task 7 移位，与 acme/pebble_test.go
# fixture 一致）；/set-txt /clear-txt 均在管理端口。
set -euo pipefail
MODE="${1:?usage: acme-dns.sh present|cleanup <fqdn> <value>}"
FQDN="${2:?missing fqdn argument}"
CHALL_URL="${CHALLTESTSRV_URL:-http://127.0.0.1:8056}"

case "${MODE}" in
  present)
    VALUE="${3:?missing TXT value argument}"
    # -f：HTTP 失败（404/500）时非零退出，暴露真实错误给 lego。
    curl -sf -X POST "${CHALL_URL}/set-txt" -H 'Content-Type: application/json' \
      -d "{\"host\":\"${FQDN}\",\"value\":\"${VALUE}\"}" >/dev/null
    ;;
  cleanup)
    curl -sf -X POST "${CHALL_URL}/clear-txt" -H 'Content-Type: application/json' \
      -d "{\"host\":\"${FQDN}\"}" >/dev/null
    ;;
  *)
    echo "acme-dns.sh: 未知模式 ${MODE}" >&2
    exit 1
    ;;
esac
