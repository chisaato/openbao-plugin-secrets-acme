# OpenBao ACME Secrets Plugin

OpenBao 的 ACME secrets engine，基于 [lego v5](https://github.com/go-acme/lego) 实现 ACME 证书自动化。v1 仅支持 **DNS-01** 挑战，支持多 DNS provider 按 zone 路由、证书共享缓存（引用计数 lease）、证书 KV 输出与 lease 驱动的自动重签。

- 插件名：`openbao-plugin-secrets-acme`
- 当前版本：`v0.1.0`
- OCI 镜像：`ghcr.io/chisaato/openbao-plugin-secrets-acme`
- 支持的 DNS provider（白名单）：`cloudflare`、`alidns`、`tencentcloud`、`exec`（任意 DNS 商兜底）

---

## 1. 安装方式 A：传统 `plugin_directory`

1. 将对应平台的二进制（[Releases](../../releases) 下载，或 `just build` 自建）放到 OpenBao 服务器的插件目录，例如 `/etc/openbao/plugins/`：

   ```sh
   sudo install -m 0755 openbao-plugin-secrets-acme_linux_amd64 \
     /etc/openbao/plugins/openbao-plugin-secrets-acme
   ```

2. 计算并校验 sha256，然后注册插件：

   ```sh
   sha256sum /etc/openbao/plugins/openbao-plugin-secrets-acme
   # <SHA256>
   bao plugin register -sha256=<SHA256> secret openbao-plugin-secrets-acme
   ```

3. 启用 secrets engine：

   ```sh
   bao secrets enable -path=acme openbao-plugin-secrets-acme
   ```

> 多节点部署时，插件二进制必须存在于**每个**节点的 `plugin_directory` 中。

## 2. 安装方式 B：声明式 `config-plugins`（OpenBao ≥ 2.5.0）

在 OpenBao 服务端配置（HCL）中声明插件，由 core 自动下载镜像并注册挂载：

```hcl
plugin "secret" "acme" {
  image        = "ghcr.io/chisaato/openbao-plugin-secrets-acme"
  version      = "v0.1.0"
  binary_name  = "openbao-plugin-secrets-acme"
  sha256sum    = "<发布产物的 SHA256，见 GitHub Release 的 SHA256SUMS>"

  # 插件进程环境注入（见下节「部署前提」）：
  env = [
    "BAO_ADDR=https://openbao.internal:8200",
    "BAO_TOKEN=<插件服务身份 token>",
  ]
}
```

并在启动配置中开启自动下载/注册（或用 `bao plugin register` 声明式等效操作）：

```hcl
plugin_auto_download = true
plugin_auto_register = true
```

随后 `bao secrets enable -path=acme openbao-plugin-secrets-acme` 即可（或由 auto-register 完成）。

## 3. 部署前提：插件进程环境（重要）

本插件在**签发时**用插件进程自身的 OpenBao API client 实时读取 DNS 凭据（KV），并在配置了 `output_kv_mount` 时把证书写回 KV。地址与身份 token 均来自**插件进程环境**：

| 环境变量 | 作用 |
| --- | --- |
| `BAO_ADDR`（或 `VAULT_ADDR`） | OpenBao API 地址 |
| `BAO_TOKEN`（或 `VAULT_TOKEN`） | **服务身份 token**，见下方权限 |
| `BAO_CACERT` / `BAO_SKIP_VERIFY` 等 | 可选 TLS 参数（自签 CA 场景） |

**服务身份 token 所需权限**（策略示例）：

- 对全部被引用的凭据 KV 路径：`read`（含 `data/` 前缀的 KVv2 路径）
- 对全部 `output_kv_mount` 目标路径：`create`/`update`（KV 写出）

**签发调用者不需要任何 KV 权限**——凭据的读取身份是插件服务身份，不是调用者 token（OpenBao 传给插件的 ClientToken 是 salted+hashed 值，不能用作访问身份；这也是必须注入专用 token 的根本原因）。

缺失 `BAO_ADDR`/`BAO_TOKEN` 时，签发会报 `create openbao client` 错误。

**两种注入方式：**

方式一，声明式 `config-plugins`（推荐，见上文 HCL 示例中的 `env = [...]`）。

方式二，传统 systemd unit：

```ini
[Service]
Environment="BAO_ADDR=https://openbao.internal:8200"
Environment="BAO_TOKEN=<插件服务身份 token>"
```

> 建议：服务身份 token 使用专用 policy + 定期轮换；不要复用人类或应用的 token。

### 3.1 服务身份 token 自动续期（renew-self）

插件启动时会以 `BAO_TOKEN` 身份对自身 token 调用一次 `auth/token/renew-self`，之后周期性续期（间隔 = 返回 TTL 的一半，下限 1 分钟；失败按指数退避 5min→30min 重试，不影响签发服务）。**renew-self 只延长过期时间、不改变 token 字符串**（服务端原 entry 持久化续期），因此环境变量里的值终身有效，无须轮换进程 env。

推荐给插件签发 **periodic token**（配合 orphan，不随父 token 过期；勿配 explicit-max-ttl，否则周期续期仍会被硬上限截断）：

```sh
bao token create -policy=acme-plugin -orphan -period=720h
```

- token 需包含 `auth/token/renew-self` 的 `update` 权限（默认 token 策略已含 `self` 路径，自定义收权时注意保留）。
- 设 `BAO_TOKEN_RENEW_DISABLE=1`（非空且非 `0`/`false` 均可）可完全关闭内置续期（已用外部机制续期、或本地 root token 测试时）。
- 本地测试用 root token 时，启动日志会出现「token 无 TTL，无需自动续期，停止续期循环」的**警告属预期**——root token 不可续期。

## 4. 快速上手

以下示例中 `<...>` 均为占位符，请替换为你的真实值。

### 4.1 把 DNS 凭据放入 KV

```sh
bao kv put secret/dns/cloudflare \
  CLOUDFLARE_DNS_API_TOKEN="<占位符>"
```

### 4.2 注册 dns-provider（凭据只存引用，不落存储）

```sh
bao write acme/dns-providers/cloudflare-primary \
  type=cloudflare \
  credentials_ref='mount=secret,path=dns/cloudflare,kv_version=2' \
  propagation_timeout=120
```

传播控制（对齐 lego v5 CLI 的 `--dns.propagation.wait` 语义）：

- `skip_propagation_check=false`（默认）：lego 主动做 DNS 传播预检（递归/权威 NS 轮询）。
- `skip_propagation_check=true`：跳过预检，`Present` 之后固定等待 `propagation_wait` 秒再通知 ACME。私有 DNS（公网查不到权威 NS）与本地测试 CA（pebble）场景必需。
- **聚合粒度注记**：预检策略在**签发请求级**聚合——account 的 `dns_providers` 列表中任一条目 `skip_propagation_check=true`，整次请求的所有域名都跳过预检（即使其他条目为 false）。混合部署时请注意这一点。

### 4.3 注册 account（ACME 账户）

```sh
bao write acme/accounts/prod \
  server_url="https://acme-v02.api.letsencrypt.org/directory" \
  contact="ops@example.com" \
  terms_of_service_agreed=true \
  key_type=EC256 \
  dns_providers='[{"name":"cloudflare-primary","zones":["example.com"]}]'
```

`dns_providers` 的 `zones` 用于路由：签发时按域名后缀匹配（zone 段数多者优先，平局按列表顺序），**`zones` 为空的条目是兜底路由**；域名无任何匹配时报错。

> **`insecure_tls` 风险注记**：开启后关闭 ACME 全流程（注册/签发/撤销）的 TLS 证书校验，**仅限 pebble 等自签/私有 CA 测试环境**；生产 CA 必须保持默认关闭。

辅助端点：

- `bao write acme/accounts/prod/rollover key_type=RSA2048` —— 账户密钥轮换（`key_type` 本体创建后不可改，换钥必须走 rollover）
- `bao read acme/accounts/prod/key` —— 导出账户私钥 PEM（**敏感**，建议仅管理员可读，见 ACL）
- `bao read acme/cache` / `bao delete acme/cache` —— 查看/清空证书缓存

### 4.4 配置 role（签发策略）

```sh
bao write acme/roles/web \
  account=prod \
  allowed_domains="example.com,*.example.com" \
  allow_bare_domains=true \
  allow_subdomains=true \
  cache_for_ratio=70 \
  output_kv_mount=certs
```

- `validateNames` 语义：`allow_any_name=true` 时放行任意域名（无需配置 `allowed_domains`）；否则按白名单校验，`*.example.com`（通配）按裸域口径放行，其余裸域需 `allow_bare_domains`，子域需 `allow_subdomains`，白名单外一律拒绝。
- `cache_for_ratio` ∈ (0,100]，默认 70：剩余寿命低于总寿命 70% 时触发重签（见「缓存与 lease」）。
- `output_kv_mount`：非空时签发结果同步写到该 KVv2 mount 的 `certs/{role}/{cn}` 路径（通配 CN 的 `*.` 前缀映射为 `_wildcard.`，`/` 映射为 `_`）；留空则不输出。
- `disable_cert_reuse`：默认 false。开启后该 role 不参与 account 级证书覆盖复用（见 §4.5「证书复用」）。

### 4.5 签发证书

```sh
# 默认异步：立即返回 job_id，由插件后台完成 DNS01 挑战与签发
bao write -field=job_id acme/certs/web common_name=www.example.com

# 轮询任务：completed 时响应含证书结果
bao read acme/jobs/<job_id>

# 同步兼容（v0.1.0 行为：阻塞至签发完成，响应带 renewable lease）
bao write -field=certificate acme/certs/web common_name=www.example.com sync=true
```

**异步任务（默认）**：`POST acme/certs/<role>` 未携带 `sync=true` 时立即返回 `job_id`/`status`/`poll_path`（不建 lease）。任务状态持久化，**插件重启（unseal/进程重启）后自动重新驱动未完成的 job**；失败不自动重试，重新提交即可。

- `bao read acme/jobs/<job_id>`：`status`（pending/processing/completed/failed）、`error`、提交信息；completed 时平铺 `certificate`/`private_key`/`issuer_cert`/`url`/`not_before`/`not_after`/`output_path`。**该读取路径不建 lease**——lease 生命周期（续期/撤销）仅绑定在 `sync=true` 的签发响应上。
- `bao list acme/jobs/`：列出全部任务；`bao delete acme/jobs/<job_id>`：删除任务（仅 completed/failed 可删）。

**同步响应（`sync=true` 与缓存/复用命中共用）**：`certificate`（PEM bundle）、`private_key`、`issuer_cert`、`common_name`、`domains`、`url`、`cert_stable_url`、`not_before`、`not_after`，以及配置了 KV 输出时的 `output_path`（**缓存命中不重写 KV**，`output_path` 指向签发时写入的数据）。响应是一个 renewable lease（TTL 上限为证书剩余寿命）。缓存/复用命中额外带 `reused: true`。

**证书复用（account 级）**：提交签发前会先在同 account 的已签发且未到期证书中查找能**覆盖全部请求域名**的条目，命中即同步返回该证书（同 lease 语义、`Users` 引用计数 +1、响应带 `reused: true`），不再重复向 CA 提单——Let's Encrypt 的速率配额按 account 计，此举可显著降低重复签发消耗。覆盖规则遵循通配符单标签语义：`*.example.com` 覆盖 `sub.example.com` 与精确的 `*.example.com`，**不覆盖**裸域 `example.com` 与多级子域 `a.b.example.com`（这两类仍走正常签发）。

## 5. 凭据模型

- **实时读取，不快照**：`dns-providers` 条目只持久化 `credentials_ref`（引用），签发时插件以服务身份实时读 KV。**轮换凭据 = 改 KV 数据，即刻生效，无须重启或重配插件。**
- `credentials_ref` 键映射（显式 keys + 同名回退）：

  ```sh
  bao write acme/dns-providers/cloudflare-primary \
    type=cloudflare \
    credentials_ref='mount=secret,path=dns/cloudflare,kv_version=2,keys={CLOUDFLARE_DNS_API_TOKEN:cf_token}'
  ```

  语义：适配层需要 lego 环境变量名 `CLOUDFLARE_DNS_API_TOKEN`，先查你在 `keys` 里映射的用户键 `cf_token`；未映射的变量回退按**同名键**在 KV 数据中查找。`kv_version` 支持 `1`/`2`（默认 2），KVv2 还可用 `version` 钉住历史版本。
- 引用有效性 fail-fast：写 `dns-providers` 时立即试读凭据并试构造 provider；签发时凭据仅存在于请求生命周期内，不落存储、不进日志、不进响应。

## 6. ACL 矩阵

| 身份 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| 签发调用者 | `acme/certs/*`、`acme/jobs/*` | `create`/`update`/`read`/`delete`/`list`（jobs） | 签发入口与任务查询；**无需任何 KV 权限** |
| 签发调用者 | `acme/*` 其余 | 无 | dns-providers/accounts/roles/cache 均为管理面 |
| 插件服务身份（`BAO_TOKEN`） | 凭据 KV 路径（如 `secret/data/dns/*`） | `read` | 实时读取 DNS 凭据 |
| 插件服务身份 | 输出 KV 路径（如 `certs/data/*`） | `create`/`update` | 证书 KV 输出 |
| 管理员 | `acme/*` | `*` | dns-providers、accounts、roles、cache 全管理 |
| 管理员（建议收紧） | `acme/accounts/*/key` | `read` 仅限管理员 | 账户私钥导出 |

签发者策略最小示例：

```hcl
path "acme/certs/*" {
  capabilities = ["create", "update"]
}

path "acme/jobs/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

## 7. 缓存与 lease

- **共享缓存**：同一 role + 同一域名集合（顺序无关）的签发共享一个缓存条目；`disable_cache=true` 则每次真签发。
- **`cache_for_ratio` 语义**：剩余寿命 < 总寿命 × ratio% 视为陈旧——签发请求命中陈旧条目会重签；lease Renew 时同样按此判断，陈旧则用原 role/account 参数重签并刷新缓存与 KV 输出，否则仅续 lease。
- **引用计数 revoke**：每个 lease 持有一个引用（`users` 计数）；撤销 lease 只减计数，**减到 0 才向 ACME 服务端真撤销**并删除缓存条目。因此多调用者共享的证书不会因单个 revoke 而失效。
- **`bao delete acme/cache` 注意事项**：清空缓存后，现存 lease 的 revoke 因找不到条目**不再触发 ACME 服务端真撤销**，只做本地引用回收；被清空的证书需等待其在服务端自然到期。请仅在了解该影响时使用。

## 8. 扩展 DNS provider

白名单在 `acme/providers.go`，扩展只需三步（PR 欢迎扩展白名单）：

1. 在 `registry` 加一行 builder：`"mydns": buildMyDNS,`
2. 在 `envNames` 声明该 provider 认识的凭据键名（即 `credentials_ref.keys` 的合法左值）：`"mydns": {"MYDNS_TOKEN", "MYDNS_SECRET"},`
3. 实现 `buildMyDNS`：从 `env map[string]string` 取键填入 lego provider 的 `Config`，套用 `applyTimeouts(opts, &cfg.PropagationTimeout, &cfg.PollingInterval)` 后经 `NewDNSProviderConfig` 构造；并在 `providers_test.go` 补对应单测。

### exec provider 兜底

任意未被白名单覆盖的 DNS 商、私有 DNS 或测试环境，可用 `exec` provider：外部脚本负责真实 DNS 写/清。

> **风险注记**：`EXEC_PATH` 指定的程序会以**插件进程的用户身份执行任意程序**，且凭据 KV 数据会传入子进程环境——属 **admin 级配置**，`EXEC_PATH` 与其凭据 KV 路径的写权限必须仅限管理员。

```sh
bao write acme/dns-providers/mydns-exec \
  type=exec \
  credentials_ref='mount=secret,path=dns/mydns,kv_version=2' \
  propagation_timeout=300 \
  skip_propagation_check=true \
  propagation_wait=30
```

其中凭据 KV 中放 `EXEC_PATH`（脚本路径；还可放 `EXEC_MODE`、`EXEC_PROPAGATION_TIMEOUT`、`EXEC_POLLING_INTERVAL`）。**凭据 map 会作为子进程环境的一部分传给脚本**（短暂私有，插件进程自身环境不注入凭据）：

- 默认（非 RAW）模式：lego v5 exec 以 argv 调用脚本——`<script> present <fqdn> <value>` / `<script> cleanup <fqdn> <value>`，`fqdn` 形如 `_acme-challenge.example.com.`（带尾点）。仓库内 `test/acme-dns.sh` 是一个可参考的完整适配脚本。
- `EXEC_MODE=RAW`：脚本按 argv 收到 `domain/token/keyAuth` 原文，自行推导 TXT 记录。

## 9. 开发

构建入口为 [just](https://github.com/casey/just)（`just --list` 查看全部目标）：

```sh
just build      # 构建 bin/openbao-plugin-secrets-acme（ldflags 注入 acme.Version）
just test       # 单测（-race），离线
just testacc    # 验收测试（test/ 独立 module，需本机 pebble + challtestsrv + bao；缺失则自动 Skip）
just vet
just release    # 交叉编译全部平台到 dist/ 并生成 SHA256SUMS
```

本地端到端验收需要 pebble（本地 ACME 测试 CA）与 challtestsrv（DNS 模拟器）。challtestsrv 自 pebble v2 主模块拆出，须用 v2 子路径安装，并固定与验收 fixture 一致的版本：

```sh
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1
```

另需 `bao` CLI（验收测试要起真实 OpenBao server）：见 [openbao releases](https://github.com/openbao/openbao/releases)。

## 10. 发布

推送 `v*` tag 触发 `release` workflow：交叉编译 6 平台二进制（linux/darwin × amd64/arm64 + linux 386/riscv64）+ `SHA256SUMS` 附到 GitHub Release，并构建 `ghcr.io/chisaato/openbao-plugin-secrets-acme` OCI 镜像（`Containerfile`，scratch 基底）推送，tag 同步 semver 标签。
