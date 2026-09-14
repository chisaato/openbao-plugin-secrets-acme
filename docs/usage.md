# 快速上手 (Usage Guide)

本文档介绍使用 OpenBao 原生 CLI (`bao`) 配置 ACME 引擎并完成证书签发的全流程。

> 💡 如果更喜欢简洁的一键式命令行体验，推荐阅读 **[CLI.md](cli.md)** 使用专用的 `bao-acme` CLI 工具。

以下示例中 `<...>` 均为占位符，请替换为真实值。

---

## 1. 存储 DNS 凭据至 KV

插件通过引用读取 KV 引擎中的 DNS API 凭据，签发时动态加载，不持久化敏感 Secret：

此处假定

- 你的 KVv2 引擎挂载于 `secret`
- 条目名称为 `dns/cloudflare`

```sh
bao kv put secret/dns/cloudflare \
  CLOUDFLARE_DNS_API_TOKEN="<你的 Cloudflare API Token>"
```

---

## 2. 注册 DNS Provider

通过 `credentials_mount` / `credentials_path` 指向刚才保存的 KV 地址：

```sh
bao write acme/dns-providers/cloudflare-primary \
  type=cloudflare \
  credentials_mount=secret \
  credentials_path=dns/cloudflare \
  credentials_kv_version=2 \
  propagation_timeout=120
```

**高级：键名映射**

当 KV 中的 Key 名与 lego 预期的环境变量名不一致时，用 `credentials_keys` 传 JSON 对象字符串（键为 lego 环境变量名，值为用户 KV 中的键名）：

```sh
bao write acme/dns-providers/aliyun \
  type=alidns \
  credentials_mount=secret \
  credentials_path=dns/aliyun \
  credentials_keys='{"ALICLOUD_ACCESS_KEY":"ak","ALICLOUD_SECRET_KEY":"sk"}'
```

可选地，`credentials_kv_version`（字符串 `"1"`/`"2"`，默认 `2`）与 `credentials_version`（整数，`0` 表示最新）用于指定 KV 引擎版本与条目版本。

### 传播控制参数（对齐 lego v5 CLI 语义）

- `skip_propagation_check=false`（默认）：lego 主动对权威/递归 NS 发起 DNS 传播预检。
- `skip_propagation_check=true`：跳过预检，执行 `Present` 写入记录后固定等待 `propagation_wait` 秒后即提交 ACME 验证。适合内网自签/Pebble 模拟测试环境。
- **聚合粒度说明**：预检策略以**整次签发请求**为粒度聚合。如果 Account 绑定的多个 Provider 中有任意一个设置了 `skip_propagation_check=true`，整批请求的域名均会跳过预检。
- **重命名 Provider**（纯本地改名，不重新校验凭据）：
  ```sh
  bao write acme/dns-providers/cloudflare-primary/rename new_name=cloudflare-main
  ```
  语义：级联更新所有 account 的 `dns_providers[].name` 引用（保留列表顺序），最后迁移条目本身。
  Provider 名不参与 cacheKey，缓存与 KV 输出无需迁移。响应 `data` 含 `old_name`/`new_name`/`migrated_accounts`。

---

## 3. 注册 Account (ACME 账户)

在指定的 ACME 服务商（如 Let's Encrypt）注册或绑定账户：

```sh
bao write acme/accounts/prod - <<'EOF'
{
  "server_url": "https://acme-v02.api.letsencrypt.org/directory",
  "contact": "mailto:ops@example.com",
  "terms_of_service_agreed": true,
  "key_type": "EC256",
  "dns_providers": [
    { "name": "cloudflare-primary", "zones": ["example.com"] }
  ]
}
EOF
```

> `dns_providers` 属于结构化复杂字段，原生 `bao` CLI 需用 JSON stdin（`bao write <path> -`）或 `@file` 引用传入；只有简单标量字段才可直接 `key=value`。上述写法也等价于 `bao write <path> - < payload.json`。

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
- **重命名账户**（纯本地改名，不调用 CA）：
  ```sh
  bao write acme/accounts/prod/rename new_name=prod-2026
  ```
  语义：级联更新引用旧账户名的 `roles` 与 `jobs`，并按新 `role.Account` 重算、
  迁移证书缓存键（先写新键再删旧键）；`output_kv_mount` 的 KV 输出迁移为尽力而为，
  失败仅在响应 `warnings` 中告警而不阻断。响应 `data` 含
  `old_name`/`new_name`/`migrated_roles`/`migrated_jobs`/`migrated_certs`，以及可选的
  `warnings`。存量 lease 仍按其旧 `cache_key` 定位条目，条目缺失时优雅降级，无需额外处理。
- **导出账户**（跨实例迁移用；载荷含私钥，高敏感）：
  ```sh
  bao read acme/accounts/prod/export
  ```
  返回 `kind`/`version`/`name`/`server_url`/`contact`/`terms_of_service_agreed`/
  `key_type`/`private_key_pem`/`registration_json`。载荷可直接作为 import 的输入；
  不含端点本地配置（`insecure_tls`、`dns_providers`），由导入方按目标环境重新指定。
- **导入账户**（纯本地恢复，除 `verify` 外不与 CA 交互；不生成新密钥、不注册）：
  ```sh
  bao write acme/accounts/prod-import/import \
    server_url="https://acme-v02.api.letsencrypt.org/directory" \
    contact="ops@example.com" \
    terms_of_service_agreed=true \
    key_type=EC256 \
    private_key_pem="$(bao read -field=private_key_pem acme/accounts/prod/export)" \
    registration_json="$(bao read -field=registration_json acme/accounts/prod/export)"
  ```
  必填：`server_url`/`key_type`/`private_key_pem`/`registration_json`；
  可选：`contact`/`terms_of_service_agreed`/`insecure_tls`/`dns_providers`/`overwrite`/`verify`。
  - `verify=true`：先向 CA 用私钥反查账户，成功则以 CA 返回刷新 `registration_json`；
    失败（私钥未在该 CA 注册或网络异常）直接报错且不落盘。
  - 目标账户名已存在时须显式 `overwrite=true`，否则报错。
  - 响应 `data` 含 `name`/`server_url`/`contact`/`key_type`/`verified`/`overwritten`。
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
  - **投影语义**：ACME 是事实源，KV 是投影。手动删除 KV 条目不会影响证书/缓存，下次签发或续期会按需恢复投影。
  - **投影状态**（缓存条目记录，可经 `GET certs/{role}/{cn}` 或 `GET certs/id/{id}` 的 `output_kv_status`/`output_kv_mount`/`output_kv_path`、以及 `LIST certs/` 摘要查看）：
    - `written`：上次成功写入，`output_kv_mount` 为成功时的 mount。
    - `skipped_conflict`：因目标被占用而跳过；`output_kv_mount` 保持"最后成功写入位置"不变。
    - `skipped_error`：因占用检查读取失败而跳过；mount 同上保持。
    - 空：未配置同步，或旧条目（零值回退）。
    - `output_kv_path`：条目记录的**完整输出路径**（`mount + "/" + certs/{cert_id}`，如 `certs/certs/abc123`），语义与 `output_kv_mount` 一致——最后成功写入的位置，跳过时保持旧值不变。展示于 `GET certs/{role}/{cn}`/`GET certs/id/{id}` 与 `LIST certs/` 摘要；旧条目未记录该字段时，展示层按记录的 mount 现场回退拼接 `mount + "/" + certs/{cert_id}`。
    撤销/引用归零时的 KV 清理优先使用条目记录的 `output_kv_mount`，为空才回退 role 现值。
  - **占用冲突**：写入前检查目标 `certs/{cert_id}` 是否已被其他证书或外来数据占用（现存数据 `cert_id` 与本次一致视为自己的旧版本，允许覆写）。冲突表现随调用方而异：
    - 同步签发（`sync=true`）：**拒绝签发**，错误含占用者详情；清理该 KV 条目，或加 `force=true` 显式覆盖。
    - 异步 Job：任务落 `failed`，`error` 说明占用详情与处理建议。
    - Lease 自动续期：跳过 KV 写并记 warning 日志，续期照常成功（响应无 `output_path`），绝不因投影冲突阻断证书续期。
- `disable_cert_reuse`：默认为 `false`。若为 `true`，该 Role 将不参与 Account 级的证书覆盖与复用机制。
- **重命名 Role**（纯本地改名）：
  ```sh
  bao write acme/roles/web/rename new_name=web-prod
  ```
  语义：cacheKey 不含 role 名，故**缓存键与 KV 输出路径不变**，仅更新引用——`jobs` 的 `role` 字段与缓存条目的 `role` 字段（原键原位覆写），最后迁移 role 条目本身。响应 `data` 含 `old_name`/`new_name`/`migrated_jobs`/`migrated_certs`。
  存量 lease 的 `InternalData["role"]` 为创建时快照；续期时会回退到缓存条目记录的签发 role 现名，自动适配改名。

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
