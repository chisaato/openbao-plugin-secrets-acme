# 部署与 Token 设置 (Deployment)

本插件在**签发证书时**需要利用插件进程自身的 OpenBao API Client 实时读取 DNS 凭据（KV），并在配置了 `output_kv_mount` 时将证书同步写回 KV。因此，插件进程必须被注入合法的服务身份 Token 与通信地址。

---

## 1. 插件进程环境配置

插件通过读取运行环境中的环境变量与 OpenBao 通信：

| 环境变量 | 作用 |
| --- | --- |
| `BAO_ADDR`（或 `VAULT_ADDR`） | OpenBao API 地址（如 `https://openbao.internal:8200`） |
| `BAO_TOKEN`（或 `VAULT_TOKEN`） | **服务身份 Token**，详见下文权限配置 |
| `BAO_CACERT` / `BAO_SKIP_VERIFY` 等 | 可选 TLS 参数（自签 CA 或内网证书场景） |
| `BAO_TOKEN_RENEW_DISABLE` | 设为 `1`/`true` 可完全关闭内置自动续期 |

缺失 `BAO_ADDR` 或 `BAO_TOKEN` 时，发起证书签发将报 `create openbao client` 错误。

---

## 2. 身份隔离与权限策略

**核心设计理念**：
- **签发调用者不需要任何 KV 权限**：凭据读取与证书写回均由插件自身的“服务身份”代劳。OpenBao 传递给插件后端的 `ClientToken` 是经过加盐哈希（salted + hashed）的值，插件无法借此代表用户身份访问 API，因此必须为插件注入专属 Token。
- **调用者与存储隔离**：业务人员/流水线仅需拥有 `acme/certs/*` 和 `acme/jobs/*` 权限，无需接触底层云厂商 API Key。

### 服务身份 Token 所需权限（最小策略）

为插件创建专用的 ACL Policy（如命名为 `acme-plugin`）：

```hcl
# 读取所有配置在 dns-providers 中的 KV 凭据路径（KVv2 路径包含 data/ 前缀）
path "secret/data/dns/*" {
  capabilities = ["read"]
}

# 若配置了 role 的 output_kv_mount 输出到 certs，需具备写权限
path "certs/data/*" {
  capabilities = ["create", "update"]
}

# 插件自身 Token 自动续期
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

---

## 3. 环境变量与插件部署方式

### 方式一：基于 OCI 镜像声明式部署（推荐，OpenBao ≥ 2.5.0）

OpenBao 原生支持通过内置 OCI 客户端从容器镜像仓库（如 GitHub Container Registry `ghcr.io`）下载插件镜像并自动解压、验证校验和、注册和注入环境变量。**宿主机或容器内无需安装 Docker 或任何容器运行时**。

#### OpenBao 服务端配置（`bao.hcl`）规范与细节

> **⚠️ OpenBao 2.5 / 2.6 的 HCL 语法注意点**：
> 1. `image` 字段**只能写仓库路径**（严禁带 `:tag` 或 `@sha256:...`），OpenBao 会自动将其与 `version` 拼接为 `image:version`。
> 2. `version` 为必填字段，对应 OCI 镜像的 Tag（例如 `"0.2.0"` 或 `"v0.1.0"`）。
> 3. `sha256sum` 为必填字段，必须是解压出来的**插件可执行二进制文件**的 64 位 SHA-256 哈希（可从 GitHub Release 的 SHA256SUMS 获取，或在本地用 `sha256sum openbao-plugin-secrets-acme` 计算），**不能使用 OCI 镜像层的 hash**。

```hcl
plugin_directory     = "/opt/openbao/plugins"
plugin_auto_download = true
plugin_auto_register = true

plugin "secret" "openbao-plugin-secrets-acme" {
  image       = "ghcr.io/chisaato/openbao-plugin-secrets-acme"
  version     = "0.2.0"
  binary_name = "openbao-plugin-secrets-acme"
  sha256sum   = "3a5ce05b2ba3425530fe772982cdbcaf221a90081dc4967702be373ab47ea80d"

  # 插件进程环境注入：
  env = [
    "BAO_ADDR=https://openbao.internal:8200",
    "BAO_TOKEN=<插件服务身份 token>",
  ]
}
```

> **工作机制说明**：
> - 当 `plugin_auto_download = true` 时，OpenBao 服务启动或接收 `SIGHUP` 时会自动从 Registry 拉取镜像，将二进制缓存在 `.oci-cache/` 中并软链接至 `plugin_directory`。
> - 当 `plugin_auto_register = true` 时，OpenBao 在解封（unseal）后自动在系统插件 Catalog 中完成注册。
> - 若使用私有 Registry，可在 OpenBao 进程宿主机配置 `~/.docker/config.json`，或设置环境变量 `REGISTRY_AUTH_FILE=/path/to/auth.json`。
> - 支持通过命令手动提前下载并解包：`bao plugin init -config=/path/to/bao.hcl`。

### 方式二：传统本地二进制 + systemd unit 文件

如果 OpenBao 运行在传统 Linux 虚拟机或物理机上且使用本地放置的二进制，可直接编辑 systemd service 文件（例如 `/etc/systemd/system/openbao.service`）：

```ini
[Service]
Environment="BAO_ADDR=https://openbao.internal:8200"
Environment="BAO_TOKEN=<插件服务身份 token>"
```

### 方式三：Kubernetes InitContainer 挂载模式

在 Kubernetes 环境中，如果 OpenBao 容器节点无法直连公网/外部 Registry，可利用 Kubernetes Pod `initContainers` 配合共享卷分发二进制：

```yaml
initContainers:
  - name: install-acme-plugin
    image: ghcr.io/chisaato/openbao-plugin-secrets-acme:v0.1.0
    command: ["cp", "/openbao-plugin-secrets-acme", "/plugins/openbao-plugin-secrets-acme"]
    volumeMounts:
      - name: plugin-volume
        mountPath: /plugins
```

OpenBao 容器挂载同一 `plugin-volume` 到 `plugin_directory`，随后通过传统注册方式或声明式指定 `command` 即可运行。

> **最佳实践**：服务身份 Token 请使用专用的 Policy + 定期轮换机制，严禁直接使用 `root` Token 或应用 Token。

---

## 4. 服务身份 Token 自动续期 (renew-self)

为避免服务身份 Token 过期导致签发中断，插件内置了自动续期守护循环：

1. **工作机制**：
   - 插件启动时，会以 `BAO_TOKEN` 身份对自身调用一次 `auth/token/renew-self`。
   - 随后按周期定时续期（续期间隔 = 返回 TTL 的 50%，下限为 1 分钟；遇到网络故障按指数退避 5min→30min 重试，不阻塞签发服务）。
   - **`renew-self` 只延长有效时间，不改变 Token 字符串**。Token 在 OpenBao 服务端的持久化状态被续期，因此进程环境里的 `BAO_TOKEN` 无需频繁重启轮换。

2. **推荐生成 Periodic Token**：
   建议配合 `-orphan` 签发 Periodic Token，使其不依赖父 Token 生命周期，且不设置 `explicit-max-ttl`（避免被硬上限截断）：

   ```sh
   bao token create -policy=acme-plugin -orphan -period=720h
   ```

3. **关闭续期**：
   如果外部已有单独的 Token 轮换工具（如 Vault-Agent / Consul-Template），或在本地使用 root token 进行功能调试，可设置环境变量 `BAO_TOKEN_RENEW_DISABLE=1`。
   > 本地使用 root token 时，日志出现「token 无 TTL，无需自动续期，停止续期循环」属于正常预期（root token 原生不可续期）。
