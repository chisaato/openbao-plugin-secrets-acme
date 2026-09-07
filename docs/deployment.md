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

## 3. 环境变量注入方式

### 方式一：声明式 `config-plugins`（推荐，OpenBao ≥ 2.5.0）

在 OpenBao 服务端配置 HCL 中声明：

```hcl
plugin "secret" "acme" {
  image       = "ghcr.io/chisaato/openbao-plugin-secrets-acme"
  version     = "v0.1.0"
  binary_name = "openbao-plugin-secrets-acme"
  sha256sum   = "<SHA256>"

  env = [
    "BAO_ADDR=https://openbao.internal:8200",
    "BAO_TOKEN=<插件服务身份 token>",
  ]
}
```

### 方式二：传统 systemd unit 文件

如果 OpenBao 运行在传统 Linux 虚拟机或物理机上，可直接编辑 systemd service 文件（例如 `/etc/systemd/system/openbao.service`）：

```ini
[Service]
Environment="BAO_ADDR=https://openbao.internal:8200"
Environment="BAO_TOKEN=<插件服务身份 token>"
```

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
