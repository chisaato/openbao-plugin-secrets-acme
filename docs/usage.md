# 快速上手 (Usage Guide)

本文档介绍使用 OpenBao 原生 CLI (`bao`) 配置 ACME 引擎并完成证书签发的全流程。

> 💡 如果更喜欢简洁的一键式命令行体验，推荐阅读 **[CLI.md](cli.md)** 使用专用的 `bao-acme` CLI 工具。

以下示例中 `<...>` 均为占位符，请替换为真实值。

---

## 1. 存储 DNS 凭据至 KV

插件通过引用读取 KV 引擎中的 DNS API 凭据，签发时动态加载，不持久化敏感 Secret：

```sh
bao kv put secret/dns/cloudflare \
  CLOUDFLARE_DNS_API_TOKEN="<你的 Cloudflare API Token>"
```

---

## 2. 注册 DNS Provider

通过 `credentials_ref` 指向刚才保存的 KV 地址：

```sh
bao write acme/dns-providers/cloudflare-primary \
  type=cloudflare \
  credentials_ref='mount=secret,path=dns/cloudflare,kv_version=2' \
  propagation_timeout=120
```

### 传播控制参数（对齐 lego v5 CLI 语义）

- `skip_propagation_check=false`（默认）：lego 主动对权威/递归 NS 发起 DNS 传播预检。
- `skip_propagation_check=true`：跳过预检，执行 `Present` 写入记录后固定等待 `propagation_wait` 秒后即提交 ACME 验证。适合内网自签/Pebble 模拟测试环境。
- **聚合粒度说明**：预检策略以**整次签发请求**为粒度聚合。如果 Account 绑定的多个 Provider 中有任意一个设置了 `skip_propagation_check=true`，整批请求的域名均会跳过预检。

---

## 3. 注册 Account (ACME 账户)

在指定的 ACME 服务商（如 Let's Encrypt）注册或绑定账户：

```sh
bao write acme/accounts/prod \
  server_url="https://acme-v02.api.letsencrypt.org/directory" \
  contact="ops@example.com" \
  terms_of_service_agreed=true \
  key_type=EC256 \
  dns_providers='[{"name":"cloudflare-primary","zones":["example.com"]}]'
```

- **Zone 路由规则**：签发时根据域名后缀自动匹配 Provider（后缀段数多的优先匹配，段数相同时按列表顺序）。**`zones` 为空的 Provider 条目作为默认兜底路由**；如果未找到任何匹配则直接报错。
- **`insecure_tls` 风险注记**：若设为 `true`，将关闭与 ACME CA 交互时的 TLS 证书校验。**严禁在生产开启，仅限 Pebble 本地测试**。

### 辅助管理端点

- **账户密钥轮换**：
  ```sh
  bao write acme/accounts/prod/rollover key_type=RSA2048
  ```
- **导出账户私钥 PEM**（高敏感权限）：
  ```sh
  bao read acme/accounts/prod/key
  ```
- **查看与清空证书缓存**：
  ```sh
  bao read acme/cache
  bao delete acme/cache
  ```

---

## 4. 配置 Role (签发策略)

Role 约束了哪些域名允许被签发、证书重签比例以及是否写出到 KV：

```sh
bao write acme/roles/web \
  account=prod \
  allowed_domains="example.com,*.example.com" \
  allow_bare_domains=true \
  allow_subdomains=true \
  cache_for_ratio=70 \
  output_kv_mount=certs
```

- **域名白名单校验**：
  - `allow_any_name=true`：放行任意域名（无需指定 `allowed_domains`）。
  - 否则基于 `allowed_domains` 严格过滤。`*.example.com` 视为通配放行，裸域需要 `allow_bare_domains=true`，二级及以上子域需 `allow_subdomains=true`。
- `cache_for_ratio`：取值区间 (0,100]，默认 70。当证书剩余有效期占总有效期的比例低于此百分比时触发重新签发。
- `output_kv_mount`：非空时签发结果同步写到指定 KVv2 mount 的 `certs/{cert_id}`（按证书全局唯一 ID 存放，避免 CN 重名冲突）。
  - 写入内容包括标准化资产字段：`cert`、`key`、`ca`、`fullchain`（叶子证书+中间证书链）。
  - 同时保留向下兼容别名：`certificate`、`private_key`、`issuer_cert`。
  - 以及扁平化元数据：`cert_id`、`common_name`、`domains`、`role`、`account`、`not_before`、`not_after`。
- `disable_cert_reuse`：默认为 `false`。若为 `true`，该 Role 将不参与 Account 级的证书覆盖与复用机制。

---

## 5. 签发证书

### 方式 A：默认异步签发（推荐）

适用于正常业务环境，避免长时间网络等待导致 HTTP 超时：

```sh
# 1. 提交签发，立即返回任务 ID
bao write -field=job_id acme/certs/web common_name=www.example.com

# 2. 轮询任务状态（当 status 为 completed 时，结果包含完整证书）
bao read acme/jobs/<job_id>
```

**异步任务运维**：
- `bao list acme/jobs/`：列出当前所有任务。
- `bao delete acme/jobs/<job_id>`：清理已完成或失败的历史任务。
- **任务容灾**：任务状态持久化存储于 Storage 中。插件若遭遇重启或 unseal，后台会自动恢复并重新驱动未完成的 Job。

### 方式 B：同步签发 (`sync=true`)

保持阻塞直到挑战与证书颁发完成，响应会携带可续期的 Lease：

```sh
bao write -field=certificate acme/certs/web common_name=www.example.com sync=true
```

响应字段包括：`certificate`（PEM bundle）、`private_key`、`issuer_cert`、`not_before`、`not_after`、`url`、`output_path` 等。若命中缓存或复用，响应中会包含 `reused: true`。
