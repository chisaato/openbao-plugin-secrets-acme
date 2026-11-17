# OpenBao ACME Secrets Plugin

OpenBao 的 ACME Secrets Engine，基于 [lego v5](https://github.com/go-acme/lego) 实现自动化证书申请与管理。插件针对 headless 生产运维优化，主要实现 **DNS-01** 挑战，支持多 DNS Provider 按 Zone 路由、凭据实时解耦、证书共享缓存（引用计数 Lease）、证书 KV 自动输出以及异步签发 Job 容灾。

- **插件名**：`openbao-plugin-secrets-acme`
- **当前版本**：`v0.1.0`
- **OCI 镜像**：`ghcr.io/chisaato/openbao-plugin-secrets-acme`
- **支持的 DNS Provider（内置白名单）**：`cloudflare`、`alidns`、`tencentcloud`、`exec`（支持任意外部脚本与私有 DNS 兜底）

---

## 核心特性

- 🔒 **凭据解耦存储**：DNS API 凭据仅保存 KV 引用，插件签发时使用服务身份实时拉取，云厂商 API Key 轮换即刻生效，无需重启插件。
- ⚡ **默认异步签发**：避免 Let's Encrypt DNS 验证延迟导致 HTTP 超时，签发任务持久化，支持 OpenBao 重启后自动恢复未完成的 Job。
- 🔄 **智能缓存与租约管理**：基于剩余有效期比例 (`cache_for_ratio`) 的自动重签机制；Lease 引用计数保证多服务共享证书时不会因单个撤销而影响其他消费者。
- ⏰ **后台自动续签**：插件周期扫描证书缓存，按 `cache_for_ratio` 阈值自动重签临期证书并刷新 KV 输出，headless 场景无需外部 cron。
- 🌐 **通配符单标签证书复用**：Account 级别自动识别已存证书范围（如 `*.example.com` 覆盖 `api.example.com`），减少 CA 速率配额消耗。
- 🛠️ **专用运维工具**：内置专为插件设计的 `bao-acme` CLI，简化日常配置与流水线运维。

---

## 文档导航

项目文档已按职责模块拆分，请查阅对应章节获取详细指南：

| 章节 | 说明 |
| --- | --- |
| 📦 **[安装指南 (install.md)](docs/install.md)** | 传统 `plugin_directory` 二进制注册与 OpenBao 2.5+ 声明式 `config-plugins` 安装 |
| 🚀 **[部署与 Token 设置 (deployment.md)](docs/deployment.md)** | 插件进程环境配置（`BAO_ADDR`/`BAO_TOKEN`）、ACL 最小权限策略与 Token 自动续期 |
| 📖 **[快速上手 (usage.md)](docs/usage.md)** | 使用原生 `bao` CLI 完成 Provider、Account、Role 配置及证书签发全流程 |
| 🏛️ **[架构设计与高级机制 (architecture.md)](docs/architecture.md)** | 凭据模型、ACL 权限矩阵、缓存/Lease 引用计数及 Account 级证书复用机制 |
| ⌨️ **[快捷运维 CLI 手册 (cli.md)](docs/cli.md)** | 基于 `bao-acme` 命令行工具的一键式运维、增量更新及批量 Job 清理 |
| 💻 **[开发与发布 (dev.md)](docs/dev.md)** | 本地构建、Pebble 端到端验收测试、扩展新 DNS Provider 及 Release 工作流 |

---

## 快速速览示例

使用内置 CLI `bao-acme` 的常见操作流程：

```sh
# 1. 挂载 Provider（关联存储在 secret/dns/cloudflare 的凭据）
bao-acme provider set cf-dns --type cloudflare --cred-path dns/cloudflare

# 2. 注册 ACME 账户
bao-acme account register prod-account \
  --server-url https://acme-v02.api.letsencrypt.org/directory \
  --contact mailto:ops@example.com \
  --provider cf-dns

# 3. 配置签发角色
bao-acme role set web prod-account \
  --allowed-domains example.com \
  --allow-bare --allow-sub

# 4. 签发证书（后台提交异步 Job，CLI 自动等待完成并保存到本地）
bao-acme cert issue web --cn example.com --alt "*.example.com" \
  --out-cert cert.pem --out-key key.pem
```

---

## 许可证

基于 MIT 协议开源。详见 [LICENSE](LICENSE)。
