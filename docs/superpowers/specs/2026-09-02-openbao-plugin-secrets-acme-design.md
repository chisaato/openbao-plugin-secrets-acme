# openbao-plugin-secrets-acme v1 设计文档

- 日期：2026-09-02
- 状态：草案（待用户审阅）
- 参考：`/data/SourceCode/vault-plugin-secrets-acme`（Boostport fork，本身基于 lego v4；复用其业务设计，重做承载层）

## 1. 背景与目标

为 OpenBao 提供 ACME 证书签发 secrets engine：

- ACME 协议实现完全交给 **go-acme/lego v5**，插件负责账户/角色/签发编排与持久化
- DNS provider 凭据集中存放于 OpenBao KV secrets engine，**签发时实时读取**，全程不使用进程环境变量
- 签发的证书**同步输出到 KV mount**，消费方用标准 `bao kv get` 取用
- 兼容 OpenBao 2.5+ 的插件分发（传统 `plugin_directory` + config-plugins RFC 的 OCI 声明式分发）

**v1 范围**：仅 DNS-01 challenge；HTTP-01 / TLS-ALPN-01 及 sidecar 推迟到 v2。

## 2. 选型与约束

| 项 | 选择 | 依据 |
|---|---|---|
| ACME 库 | `github.com/go-acme/lego/v5` v5.4.1 | 当前主线；需 go 1.26+；`KeyRollover`、`ResolveAccountByKey` 现成可用 |
| 插件 SDK | `github.com/openbao/openbao/sdk/v2` v2.6.2 | OpenBao 官方 SDK |
| API 客户端 | `github.com/openbao/openbao/api/v2` v2.6.0 | 插件进程内读/写 KV |
| 仓库形态 | 单 Go module 单仓库 | 用户无法推送到官方 monorepo；参照 openbao-plugin-secrets-oauthapp |
| 插件形态 | 外部插件进程，`framework.Backend` + `plugin.ServeMultiplex` + `RunningVersion`（v 前缀 SemVer） | OpenBao 官方插件架构 |
| DNS provider 白名单 | cloudflare、alidns、tencentcloud | 用户指定；**注意 dnspod provider 已被 lego v5 移除，官方替代为 tencentcloud** |
| 账户 key rollover | v1 提供（lego `Registration.KeyRollover`） | RFC 8555 §7.3.5 支持换 key（含 RSA→ECC） |

## 3. 架构总览

```
├── acme/                          # 核心包
│   ├── backend.go                 # Factory + Paths + Secrets 注册
│   ├── account.go                 # lego User 实现（账户重建自存储）
│   ├── path_dnsproviders.go       # dns-providers/{name}
│   ├── path_accounts.go           # accounts/{name}（+ rollover 子路径）
│   ├── path_roles.go              # roles/{name}
│   ├── path_certs.go              # certs/{role} 签发
│   ├── path_cache.go              # cache 查看/清空
│   ├── credentials.go             # credentials_ref → KV 读取（接口化便于测试）
│   ├── dnsprovider_registry.go    # provider 适配注册表
│   ├── routing_provider.go        # 复合 challenge.Provider（按域名路由）
│   ├── cache.go                   # 证书缓存（引用计数 + singleflight）
│   ├── kv_output.go               # 证书同步写 KV mount
│   └── secret_cert.go             # cert secret（Renew/Revoke）
├── cmd/plugin/main.go             # 插件入口
├── test/                          # 验收测试 + pebble 配置
└── .github/workflows/             # CI + 发布
```

## 4. API 设计

### 4.1 `dns-providers/{name}`（CRUD + LIST）

| 字段 | 类型 | 约束 |
|---|---|---|
| `type` | string | 必填；`cloudflare` \| `alidns` \| `tencentcloud`；**创建后不可改** |
| `credentials_ref` | map | 必填，见 §5 |
| `propagation_timeout` | int (秒) | 可选，透传给 provider Config |
| `polling_interval` | int (秒) | 可选，透传给 provider Config |

- 创建/更新时：用调用者 token **试读一次** KV 校验引用有效（fail fast），**不快照内容**
- 删除时：校验无 account 引用，否则拒绝

### 4.2 `accounts/{name}`（CRUD + LIST + rollover + key 导出）

| 字段 | 类型 | 约束 |
|---|---|---|
| `server_url` | string | 必填（ACME directory URL）；**允许修改** |
| `contact` | string | 必填（邮箱） |
| `terms_of_service_agreed` | bool | 必须为 true 才能创建 |
| `key_type` | string | 默认 `EC256`；白名单 EC256/EC384/RSA2048/RSA4096/RSA8192；**创建后不可改**（改 key 走 rollover） |
| `dns_providers` | list | 必填；`[{name, zones?: [suffix...]}]`；`name` 必须是已存在的 dns-providers 条目；**无 `zones` 的条目作为兜底** |

行为：

- **创建**：生成账户私钥（`certcrypto.GeneratePrivateKey`）→ `Registration.Register({TermsOfServiceAgreed})` → 持久化 `registration_uri` + 私钥（PEM PKCS8）
- **修改 `server_url`**：同一把 key 在新 CA 重新 `Register`（LE staging/production 账户按环境隔离，协议与 LE 均允许；配 `ResolveAccountByKey` 做幂等）。更新时立即执行，失败则拒绝修改
- **删除**：调用 lego 账户注销 API（`Registration.DeactivateAccount`，实现时以 lego v5 实际方法名为准）后删除存储
- **`POST accounts/{name}/rollover`**：body `{key_type}` → 生成新私钥 → `Registration.KeyRollover(ctx, newKey)` → 更新存储中私钥与 `key_type`
- **`GET accounts/{name}/key`**：导出账户私钥（PEM PKCS8），响应 `data`: `{private_key, key_type}`。不做额外限制（用户明确要求开放此行为；文档注明：持有此 key 即持有该 ACME 账户身份，路径 ACL 建议仅限管理员）

### 4.3 `roles/{name}`（CRUD + LIST）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `account` | string | — | 必填，存在性校验 |
| `allowed_domains` | CommaStringSlice | [] | 域名白名单 |
| `allow_bare_domains` | bool | false | |
| `allow_subdomains` | bool | false | |
| `disable_cache` | bool | false | |
| `cache_for_ratio` | int | 70 | 0 < x ≤ 100；剩余寿命占比阈值 |
| `output_kv_mount` | string | "" | 可选；设置后签发结果同步写入该 KV mount |

### 4.4 `certs/{role}`（POST 签发）

- 入参：`common_name`（必填）、`alternative_names`（逗号分隔）
- 域名校验：沿用参考仓库 `validateNames` 语义（bare/subdomain 与 PKI 引擎一致）
- 响应 `data`：`common_name`、`domains`、`certificate`、`private_key`、`issuer_cert`、`url`、`cert_stable_url`、`not_before`、`not_after`；启用 KV 输出时附 `output_path`
- `Secret.MaxTTL = time.Until(notAfter)`；`InternalData`: `account`、`cache_key`

### 4.5 `cache`（GET 数量 / DELETE 清空）

沿用参考仓库。

### 4.6 域名 → provider 路由语义

对请求中每个域名（wildcard 先去掉 `*.` 前缀）在 `account.dns_providers` 中匹配：

1. `zones` 后缀匹配（域名等于 zone 或为其子域）
2. zone 段数多者优先（精度优先，如 `sys.example.com` 胜过 `example.com`）
3. 平局按列表顺序（先出现者胜）
4. 无任何匹配（含无兜底条目）→ 签发失败，错误信息列出可用 zones

（语义对齐 cert-manager solver picker，源码级确认。）

## 5. 凭据模型（核心）

### 5.1 credentials_ref 结构

```json
{
  "mount": "kv",
  "path": "dns-providers/cloudflare-prod",
  "kv_version": "2",
  "keys": { "CLOUDFLARE_DNS_API_TOKEN": "my_cf_token" }
}
```

- `keys`：左键 = 适配层所需的 **lego 标准环境变量名**（固定）；右值 = 用户 KV 数据中的实际 key 名（任意）
- **缺省回退**：`keys` 省略，或某个变量名未映射时，按同名 key 查找——单用途 secret 零配置，多用途 secret 显式映射（K8S SecretRef 风格）

### 5.2 读取时机与身份

- **签发时实时读**：`req.ClientToken` 构造 `api.NewClient` → 按 `kv_version` 走 KVv2（`/data/` 前缀）或 KVv1 → `map[string]string`
- **改 KV 即轮换**：无须重启、无须重写 account（kv_version=2 时也可用 `version` 锁定具体版本——预留字段）
- 凭据**永不落插件存储、不回显、不进日志**
- `credentials.go` 抽象为接口（`loadCredentials(ctx, token, ref)`），便于单测注入

### 5.3 ACL 要求（写进 README）

- 签发调用者需对 `credentials_ref` 指向路径的 `read` 权限
- 启用 `output_kv_mount` 时，签发调用者需对该输出路径的 `write`（`create`/`update`）权限

## 6. DNS provider 适配层

### 6.1 注册表

```go
// acme/dnsprovider_registry.go
type builder func(creds map[string]string, opts providerOpts) (challenge.Provider, error)

var registry = map[string]builder{
    "cloudflare":    buildCloudflare,    // v1 内置
    "alidns":        buildAliDNS,        // v1 内置
    "tencentcloud":  buildTencentCloud,  // v1 内置
}
```

每个 builder 显式映射（凭据键数量少，手写映射比反射可靠）：

| provider | 变量名 → Config 字段 |
|---|---|
| cloudflare | `CLOUDFLARE_DNS_API_TOKEN`→AuthToken、`CLOUDFLARE_ZONE_API_TOKEN`→ZoneToken、`CLOUDFLARE_EMAIL`→AuthEmail、`CLOUDFLARE_API_KEY`→AuthKey |
| alidns | `ALICLOUD_ACCESS_KEY`→APIKey、`ALICLOUD_SECRET_KEY`→SecretKey、`ALICLOUD_SECURITY_TOKEN`→SecurityToken |
| tencentcloud | `TENCENTCLOUD_SECRET_ID`→SecretID、`TENCENTCLOUD_SECRET_KEY`→SecretKey |

- 缺必填凭据 → 明确报错（列出该 provider 需要的变量名）
- go.mod 仅 import 这三个 provider 包（避免参考仓库全量 import 导致的依赖树爆炸）
- **扩展新 provider = 实现 builder + 注册表加一行**（文档记录步骤）

### 6.2 复合路由 provider

```go
// acme/routing_provider.go
// 实现 lego challenge.Provider；Present/CleanUp(ctx, domain, token, keyAuth)
// 按 §4.6 语义匹配域名后委托给子 provider
```

- lego v5 原生单 provider 槽位，但 `Present/CleanUp` 每次携带域名——自实现路由无需 fork
- `Timeout()` 返回各子 provider 中最保守（最大）值
- 路由表只读、无共享可变状态 → 天然并发安全（lego prober 会并行 PreSolve）

## 7. 签发 / 缓存 / lease / revoke

- **签发**：解析路由 → 构造 providers → 重建 lego Client（账户自存储）→ `SetDNS01Provider(routingProvider)` → `Certificate.Obtain{Domains, Bundle: true}`（插件不生成 CSR）
- **缓存**：键 = `sha256(roleJSON + 域名集)`；首次签发建条目（引用计数 = 1）；命中且剩余寿命 ≥ `cache_for_ratio%` × 总寿命 → 直接返回（引用计数 +1）；过期 → 重签覆盖（引用计数重置为 1）。`disable_cache` 角色跳过缓存。注意：`cache` DELETE 清空后，现存 lease 的 revoke 将找不到条目、不再触发真撤销——文档需注明该操作为管理性动作
- **并发修正**：参考仓库全局 Mutex → **RWMutex + 按缓存键 singleflight**（不同域名组合可并发签发）
- **Renew 修正**（替代参考仓库 `TTL+=Increment` hack）：renew 回调检查剩余寿命，低于阈值 → 重签（刷新 KV 输出）→ 返回新证书数据；否则原样续 lease
- **Revoke**：lease revoke → 引用计数 `-1` → 归零时删除缓存条目 + `Certificate.Revoke`；**KV 输出不自动删除**（文档说明，消费方可能仍需旧证书）
- **KV 输出**：签发/重签成功后写 `{output_kv_mount}` 的 `certs/{role}/{cn}`（CN 含 `*.` 时 sanitize 为 `_wildcard.`）；内容：`certificate`、`private_key`、`issuer_cert`、`domains`、`not_before`、`not_after`；缓存命中不重写

## 8. 存储布局（插件 barrier 内）

| 键 | 内容 |
|---|---|
| `accounts/{name}` | server_url、registration_uri、contact、tos_agreed、private_key(PEM PKCS8)、key_type、dns_providers[] |
| `dns-providers/{name}` | type、credentials_ref、propagation_timeout、polling_interval |
| `roles/{name}` | role JSON |
| `cache/{sha256}` | Users(引用计数)、Account、Domains、CertURL、CertStableURL、PrivateKey、Certificate、IssuerCertificate |

（v1 无 `challenges/` 前缀。）

## 9. 测试策略

- **单元测试**：pebble + pebble-challtestsrv 子进程 + `InmemStorage` 直连 `HandleRequest`；DNS-01 用**测试专用 fake builder** 注入注册表；凭据读取经 `credentials.go` 接口 mock；覆盖账户 CRUD/rollover、路由矩阵、签发+缓存命中+renew+双重 revoke
- **验收测试**：`bao server -dev`（内置 `secret/` KV v2）→ 预置凭据 KV → 建 dns-provider/account/role → lego **exec provider**（脚本调 challtestsrv set-txt/clear-txt）→ 签发 → **断言 KV 输出内容** → lease revoke → pebble `:15000 cert-status-by-serial` 验证真实证书状态。覆盖"实时读 KV"与"同步写 KV"全链路
- **CI**：安装 pebble + OpenBao，`make test` + `make testacc`

## 10. 插件入口与发布

- 入口：`api.PluginAPIClientMeta` 解析 TLS → `plugin.ServeMultiplex(&plugin.ServeOpts{BackendFactoryFunc, TLSProviderFunc})`；`RunningVersion` 由 ldflags 注入
- **发布物**：GitHub Releases 多平台二进制 + sha256；ghcr.io OCI 镜像（`FROM scratch` + COPY 二进制，`binary_name = openbao-plugin-secrets-acme`）
- **两种安装路径**（README 均覆盖）：
  1. 传统：`bao plugin register -sha256=... secret openbao-plugin-secrets-acme` → `bao secrets enable <name>`
  2. 声明式（config-plugins RFC，OpenBao 2.5+）：

     ```hcl
     plugin "secret" "acme" {
       image       = "ghcr.io/<org>/openbao-plugin-secrets-acme"
       version     = "v0.1.0"
       binary_name = "openbao-plugin-secrets-acme"
       sha256sum   = "<release sha256>"
     }
     ```

## 11. v2 展望（不进 v1）

- HTTP-01 / TLS-ALPN-01：challenges 存储端点 + sidecar 二进制（参考仓库职责划分）
- 更多 DNS provider（注册表按需扩展）
- `output` 路径模板化、ACME Profile / ARI（lego `ObtainRequest` 已支持）

## 12. 参考链接

- 参考仓库关键文件：`acme/backend.go`、`acme/path_*.go`、`acme/cache.go`、`acme/secret_cert.go`、`test/acceptance_test.go`
- OpenBao：插件架构 https://openbao.org/docs/plugins/plugin-architecture/ ；声明式插件 https://openbao.org/docs/configuration/plugins/ ；RFC https://openbao.org/community/rfcs/config-plugins/
- lego：https://go-acme.github.io/lego/usage/library/ ；v5 迁移 https://github.com/go-acme/lego/blob/main/docs/content/migration/library.md
- RFC 8555（§7.3.5 account key rollover）
- cert-manager solver picker：`pkg/util/solverpicker/solverpicker.go`（路由语义来源）
