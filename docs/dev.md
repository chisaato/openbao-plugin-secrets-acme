# 开发与发布 (Development & Release)

本文档面向插件开发者与贡献者，介绍环境构建、单测与端到端验收测试、扩展新的 DNS Provider 以及版本发布流水线。

---

## 1. 本地构建与代码风格

项目使用 [just](https://github.com/casey/just) 作为任务管理入口，运行 `just --list` 查看所有目标：

```sh
just build      # 编译 bin/openbao-plugin-secrets-acme 插件及 bin/bao-acme CLI
just test       # 运行离线单元测试（包含 -race 检测）
just vet        # 执行 Go 代码静态检查
just release    # 本地模拟交叉编译全部 6 平台二进制到 dist/ 并生成 SHA256SUMS
```

---

## 2. 端到端本地验收测试 (Acceptance Test)

验收测试套件位于 `test/` 独立子模块，采用真实环境模拟端到端链路。

### 前置依赖工具

本地端到端测试依赖真实运行的 `openbao` CLI 以及 Let's Encrypt 官方的本地模拟工具：

1. **Pebble**（本地轻量 ACME CA 服务）与 **challtestsrv**（DNS 挑战应答服务）：
   ```sh
   go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
   go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1
   ```
2. **OpenBao 二进制 (`bao`)**：
   下载并放置在 `$PATH` 中，详见 [OpenBao Releases](https://github.com/openbao/openbao/releases)。

### 运行验收测试

```sh
just testacc
```

> **自动降级**：若检测到本地缺少 `pebble`、`challtestsrv` 或 `bao`，验收测试将自动 Skip，不会阻断普通单元测试。更多环境准备细节可参阅 [docs/local-testing.md](local-testing.md)。

---

## 3. 扩展新的 DNS Provider

DNS Provider 白名单与构造适配器定义在 `acme/providers.go`。若需要支持新的云厂商，仅需三步（非常欢迎提交 PR）：

1. **注册 Builder 函数**：
   在 `registry` 映射中增加一行：
   ```go
   "mydns": buildMyDNS,
   ```
2. **声明凭据 Key 白名单**：
   在 `envNames` 中声明该 Provider 所需的环境变量名称（即 `credentials_keys` JSON 映射的合法目标）：
   ```go
   "mydns": {"MYDNS_TOKEN", "MYDNS_SECRET"},
   ```
3. **编写 Provider 适配工厂**：
   实现对应的 `buildMyDNS(ctx context.Context, env map[string]string, opts ProviderOptions)`：
   - 从 `env` 中提取所需配置填入 lego provider 的 `Config` 结构体；
   - 调用 `applyTimeouts(opts, &cfg.PropagationTimeout, &cfg.PollingInterval)` 统一超时与轮询策略；
   - 调用 lego 的 `NewDNSProviderConfig(cfg)` 实例化；
   - 在 `acme/providers_test.go` 中补充构造单元测试。

### 使用 `exec` Provider 兜底

对于暂未纳入白名单的私有 DNS、小众 DNS 商或内部测试系统，可直接使用 `exec` Provider 驱动自定义外部脚本：

```sh
bao write acme/dns-providers/mydns-exec \
  type=exec \
  credentials_mount=secret \
  credentials_path=dns/mydns \
  credentials_kv_version=2 \
  propagation_timeout=300 \
  skip_propagation_check=true \
  propagation_wait=30
```

- **安全审计**：`EXEC_PATH` 运行的程序将以**插件进程自身的 Linux 用户身份运行**，且凭据 KV 内容会注入子进程环境变量中。此项属于管理员最高风险配置，必须仅对管理员开放修改权限。
- **命令行契约**：
  - **默认模式**：标准 lego exec 接口，脚本接收两个参数：`<script> present <fqdn> <value>` 与 `<script> cleanup <fqdn> <value>`。仓库中提供了 `test/acme-dns.sh` 作为标准实现样例。
  - **RAW 模式 (`EXEC_MODE=RAW`)**：脚本接收 `domain/token/keyAuth` 原文，由脚本自行派生 TXT 记录内容。

---

## 4. 版本发布 (Release Workflow)

项目采用自动化 GitHub Actions 流水线发布：

1. 检出目标分支并打上符合 SemVer 规则的 Tag 并推送：
   ```sh
   git tag -a v0.1.1 -m "Release v0.1.1"
   git push origin v0.1.1
   ```
2. 触发 `release` workflow：
   - 自动交叉编译 6 平台产物（`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `linux/386`, `linux/riscv64`）。
   - 计算并生成 `SHA256SUMS` 文件，自动挂载到 GitHub Release 页面。
   - 基于 `Containerfile`（scratch 基底）构建并推送 OCI 镜像至 GitHub Container Registry：
     `ghcr.io/chisaato/openbao-plugin-secrets-acme:<tag>`。
