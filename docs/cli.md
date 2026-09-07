# bao-acme CLI 使用手册

`bao-acme` 是专门用于管理 `openbao-plugin-secrets-acme` 插件的命令行工具，基于 Cobra 构建。它封装了 OpenBao 的标准 HTTP API，简化了账户注册、DNS Provider 配置、Role 策略调整、异步证书签发及状态轮询等高频操作。

---

## 1. 编译与环境准备

### 编译
```bash
just build
# 生成的二进制文件位于 bin/bao-acme
```

### 全局环境变量与 Flags
CLI 默认会自动读取标准环境变量，无须每次输入连接参数：

| 环境变量 | 命令行 Flag | 默认值 | 说明 |
|---|---|---|---|
| `BAO_ADDR` / `VAULT_ADDR` | `--address` | `http://127.0.0.1:8200` | OpenBao 服务监听地址 |
| `BAO_TOKEN` / `VAULT_TOKEN` | `--token` | 空 | 访问 Token（亦可登录后保存在 `~/.vault-token`） |
| `ACME_MOUNT` | `--mount` | `acme` | ACME 插件在 OpenBao 中的挂载路径 |
| - | `-f, --format` | `text` | 输出格式：`text` 或 `json` |

---

## 2. 子命令详解

### 2.1 Provider 管理 (`bao-acme provider`)

用于配置 DNS-01 验证所依赖的 DNS 服务商凭据引用与传播参数。

#### `provider set <name>`
配置或更新一个 DNS Provider。

**参数列表：**
- `--type` (必填)：Provider 类型。例如 `alidns`, `tencentcloud`, `cloudflare`, `exec` 等（必须是支持的白名单类型）。
- `--cred-mount`：凭据所在的 KV mount 名称（默认 `secret`）。
- `--cred-path` (必填)：凭据所在的 KV 相对路径。例如凭据放在 `secret/data/dns/ali`，则此处填 `dns/ali`。
- `--prop-timeout`：DNS 记录传播超时（默认 `2m`）。
- `--poll-interval`：DNS 记录查询轮询间隔（默认 `2s`）。
- `--skip-check`：布尔值，是否跳过 lego 本地递归预检（适用于本地网络受污染、无法解析权威 NS 或本地 Pebble 环境）。
- `--prop-wait`：整数，跳过预检时的固定等待时间（秒，如 `60` 表示 Present 后固定等待 60 秒再提交 ACME CA）。
- `--resolvers`：自定义上游递归 DNS 服务器（如 `223.5.5.5:53,1.1.1.1:53`），避开宿主机/容器内污染 DNS。

```bash
# 示例 1：全新创建 Cloudflare Provider
bao-acme provider set my-cf \
  --type cloudflare \
  --cred-mount secret \
  --cred-path dns/cf

# 示例 2：增量更新已有 Provider（支持部分字段单独覆盖，无需重复传 type 与凭据）
bao-acme provider set my-cf \
  --resolvers "223.5.5.5:53,1.1.1.1:53" \
  --skip-check \
  --prop-wait 60
```

#### `provider get <name>` / `provider list` / `provider delete <name>`
```bash
bao-acme provider list
bao-acme provider get my-ali
bao-acme provider delete my-ali
```

---

### 2.2 账户管理 (`bao-acme account`)

用于向 ACME CA 注册账户私钥，并将 DNS Provider 绑定至账户。

#### `account register <name>`
注册新账户并完成 ToS 同意与私钥生成。

**参数列表：**
- `--server-url` (必填)：ACME CA Directory URL。
  - Let's Encrypt 生产：`https://acme-v02.api.letsencrypt.org/directory`
  - Let's Encrypt 测试：`https://acme-staging-v02.api.letsencrypt.org/directory`
  - ZeroSSL：`https://acme.zerossl.com/v2/DV90`
- `--contact` (必填)：联系方式，如 `mailto:admin@example.com`。
- `--provider` (可重复多次)：关联已配置的 DNS Provider。格式支持：
  - `name`：作为全局兜底 provider；
  - `name:zone1,zone2`：仅当域名属于指定 zone 时路由到该 provider。
- `--key-type`：账户私钥算法（默认 `EC256`，可选 `EC384`, `RSA2048`, `RSA4096`）。
- `--agree-tos`：同意服务条款（默认 `true`）。
- `--insecure-tls`：跳过 CA TLS 证书验证（仅测试环境使用）。

```bash
# 示例：注册账户并绑定阿里云 DNS
bao-acme account register le-staging \
  --server-url https://acme-staging-v02.api.letsencrypt.org/directory \
  --contact mailto:ops@example.com \
  --provider my-ali

# 示例：多 Provider 路由（子域分别路由）
bao-acme account register multi-cloud \
  --server-url https://acme-v02.api.letsencrypt.org/directory \
  --contact mailto:ops@example.com \
  --provider "ali:example.com,example.cn" \
  --provider "cf:example.org"
```

#### `account get <name>` / `account list` / `account deactivate <name>`
```bash
bao-acme account list
bao-acme account get le-staging
bao-acme account deactivate le-staging
```

---

### 2.3 Role 策略管理 (`bao-acme role`)

Role 用于定义签发策略（域名白名单范围、缓存寿命、是否允许泛域名覆盖复用等）。

#### `role set <name>`（支持字段单独覆盖）
创建新 Role 或**覆盖修改已有 Role 的指定字段**。未在命令行中声明的 flag 保持已有配置不变！

**参数说明与输入指引：**

| 参数 | 类型 | 输入示例 | 说明 |
|---|---|---|---|
| `--account` | 字符串 | `le-staging` | 绑定的 ACME 账户名称（首次创建时必填） |
| `--allowed-domains` | 字符串列表 | `example.com,test.org` | 允许签发的白名单主域名（逗号分隔） |
| `--allow-bare` | 布尔值 | `--allow-bare` 或 `--allow-bare=false` | 是否允许签发白名单域自身（如 `example.com`） |
| `--allow-sub` | 布尔值 | `--allow-sub` 或 `--allow-sub=false` | 是否允许签发子域或通配域（如 `app.example.com`、`*.example.com`） |
| `--allow-any` | 布尔值 | `--allow-any` 或 `--allow-any=false` | 是否允许签发任意域名（绕过白名单校验） |
| `--disable-cache` | 布尔值 | `--disable-cache` 或 `--disable-cache=false` | 是否完全禁用证书缓存（每次请求都强制走 ACME 真实签发） |
| `--disable-reuse` | 布尔值 | `--disable-reuse` 或 `--disable-reuse=false` | 是否禁用同账户泛域名覆盖复用（例如已有 `*.example.com` 证书，默认会直接复用服务 `app.example.com`，设为 true 则禁止） |
| `--cache-ratio` | 整数 (1-100) | `80` | 缓存证书有效期百分比，剩余寿命低于该值时才触发重新签发（默认 70） |
| `--output-kv` | 字符串 | `secret` | 签发成功后是否将证书与私钥镜像写入指定 KV-v2 挂载点（留空则不写入） |

#### 针对"单独字段覆盖"的实操示例：
```bash
# 1. 首次创建完整 Role:
bao-acme role set web \
  --account le-staging \
  --allowed-domains example.com \
  --allow-bare --allow-sub \
  --output-kv secret

# 2. 场景 A：只想单独更新白名单域名，其他所有配置（account/output-kv等）都不变：
bao-acme role set web --allowed-domains "example.com,api.example.com,site.org"

# 3. 场景 B：只想单独开启/关闭泛域名覆盖复用：
bao-acme role set web --disable-reuse=true   # 禁用复用
bao-acme role set web --disable-reuse=false  # 重新启用复用

# 4. 场景 C：只想单独调整证书续签缓存阈值：
bao-acme role set web --cache-ratio 85
```

#### `role get <name>` / `role list` / `role delete <name>`
```bash
bao-acme role list
bao-acme role get web
bao-acme role delete web
```

---

### 2.4 证书生命周期管理 (`bao-acme cert`)

`cert` 命令提供对证书资产的完整生命周期管理（申请、检索、详情查看、主动续签与撤销删除）。

#### 常用命令概览：
| 命令 | 说明 |
|---|---|
| `cert list [--role <role>]` | 列出已签发或已缓存的证书（支持指定 Role 过滤） |
| `cert get <role> <cn>` | 查看指定证书详情（可直接将公私钥导出至文件） |
| `cert issue <role> --cn <cn>` | 申请签发新证书（默认异步轮询等待，支持直接导出本地文件） |
| `cert renew <role> <cn>` | 主动触发已有证书的续签 |
| `cert revoke <role> <cn>` | 撤销证书并从集群缓存和存储中清理 |

#### 1. 列出证书 (`cert list`)
```bash
# 列出系统内所有证书
bao-acme cert list

# 输出格式示例：
# COMMON NAME                    ROLE            ACCOUNT         EXPIRES AT (UTC)
# ------------------------------------------------------------------------------------------
# example.com                    web             le-staging      2026-12-05T12:00:00Z
# api.example.com                web             le-staging      2026-12-05T12:00:00Z

# 仅列出指定 Role 下的证书
bao-acme cert list --role web
```

#### 2. 查看与导出证书 (`cert get`)
```bash
# 在终端查看证书详细信息（包含有效期、所属 Account/Role、SAN 域名列表及 PEM 内容）
bao-acme cert get web example.com

# 提取并导出证书链与私钥到本地文件
bao-acme cert get web example.com --out-cert /etc/ssl/cert.pem --out-key /etc/ssl/key.pem
```

#### 3. 申请签发证书 (`cert issue`)
发起证书签发。**默认行为：提交异步任务，并在终端输出轮询进度，完成后直接输出或保存证书。**

支持类似 `acme.sh` 的 `-d / --domain` 多域名语法（可重复传入或逗号分隔，首个域名为主域名 CN，后续为 SAN 扩展域名），也可以继续使用 `--cn` 和 `--alt`。

```bash
# 示例 1：使用类似 acme.sh 的 -d 语法签发单域或多域名证书
bao-acme cert issue web -d example.com -d "*.example.com" \
  --out-cert /etc/ssl/cert.pem \
  --out-key /etc/ssl/key.pem

# 示例 2：请求子域名，自动复用上面刚签发的泛域名证书（毫秒级返回）
bao-acme cert issue web -d app.example.com
# 终端提示：命中已有证书覆盖复用 (reused: true)，并直接打印证书内容

# 示例 3：单次签发覆盖 DNS-01 预检（指定 223.5.5.5 上游 DNS，或跳过本地预检）
bao-acme cert issue web -d example.com \
  --resolvers "223.5.5.5:53,1.1.1.1:53" \
  --skip-check \
  --prop-wait 60

# 示例 4：仅提交后台任务（脚本自动化场景）
JOB_ID=$(bao-acme cert issue web -d example.com --no-wait -f json | jq -r .job_id)
echo "后台任务 ID: $JOB_ID"
```

> **DNS-01 幂等写入特性**：
> 插件内置了针对 Cloudflare（如 `81058: An identical record already exists`）以及各大主流 DNS 服务商的幂等容错包装。若由于前次任务异常中断导致 DNS 记录已存在，当前任务的 Present 阶段会自动将其识别为成功并继续执行，避免报 400 失败。

#### 4. 主动触发续签 (`cert renew`)
当需要强制向 CA 重新签发证书（即便未到达 `cache-ratio` 阈值）时使用：
```bash
# 提交续签任务（默认异步）
bao-acme cert renew web example.com

# 同步等待续签完成
bao-acme cert renew web example.com --sync
```

#### 5. 撤销证书并清理 (`cert revoke`)
立即向 ACME CA 发送 Revoke 请求撤销证书，并从 OpenBao 存储与本地缓存中彻底清理条目：
```bash
bao-acme cert revoke web example.com
```

---

### 2.5 异步 Job 管理 (`bao-acme job`)

当使用 `--no-wait` 或在服务重启后排查任务状态时使用。

#### 常用命令：
```bash
# 列出所有任务 (表格对齐展示状态、域名、相对时间 Age 与错误摘要)
bao-acme job list

# 查询指定任务详情（含当前状态、更新时间、证书快照与失败原因）
bao-acme job get <job_id>

# 在终端等待指定任务完成（若已处于完成/失败态则立即返回）
bao-acme job wait <job_id> --timeout 5m

# 自动清理终态任务记录 (默认清理所有已完成和已失败的 Job)
bao-acme job prune

# 仅清理执行失败的 Job，并跳过交互确认
bao-acme job prune --failed-only -y

# 清理超过 24 小时的终态 Job
bao-acme job prune --older-than 24h -y

# 删除指定单个任务记录（仅 completed 或 failed 状态允许删除，进行中的不可删除）
bao-acme job delete <job_id>
```
