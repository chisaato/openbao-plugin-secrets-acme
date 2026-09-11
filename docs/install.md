# 安装指南 (Installation)

`openbao-plugin-secrets-acme` 支持两种安装方式：传统手动注册（适用于所有 OpenBao 版本）和声明式 `config-plugins` 自动管理（OpenBao ≥ 2.5.0）。

---

## 1. 安装方式 A：传统 `plugin_directory`

适用于任意 OpenBao 版本：

1. **放置二进制文件**  
   将对应平台的二进制（从 [Releases](https://github.com/chisaato/openbao-plugin-secrets-acme/releases) 下载，或通过 `just build` 自建）复制到 OpenBao 服务器的插件目录（例如 `/etc/openbao/plugins/`）：

   ```sh
   sudo install -m 0755 openbao-plugin-secrets-acme_linux_amd64 \
     /etc/openbao/plugins/openbao-plugin-secrets-acme
   ```

2. **计算并校验 SHA256，注册插件**  
   计算二进制哈希，并告知 OpenBao 核心：

   ```sh
   sha256sum /etc/openbao/plugins/openbao-plugin-secrets-acme
   # <SHA256>
   bao plugin register -sha256=<SHA256> secret openbao-plugin-secrets-acme
   ```

3. **启用 secrets engine**  
   将插件挂载到指定的路径（例如 `acme/`）：

   ```sh
   bao secrets enable -path=acme openbao-plugin-secrets-acme
   ```

> **集群注意**：多节点部署时，插件二进制文件必须存在于**每个**节点的 `plugin_directory` 中。

---

## 2. 安装方式 B：声明式 `config-plugins`（OpenBao ≥ 2.5.0）

在 OpenBao 服务端配置（HCL）中直接声明插件，由 core 自动拉取 OCI 镜像并注册挂载：

```hcl
plugin_directory     = "/opt/openbao/plugins"
plugin_auto_download = true
plugin_auto_register = true

plugin "secret" "openbao-plugin-secrets-acme" {
  image        = "ghcr.io/chisaato/openbao-plugin-secrets-acme"
  version      = "0.2.0"
  binary_name  = "openbao-plugin-secrets-acme"
  sha256sum    = "3a5ce05b2ba3425530fe772982cdbcaf221a90081dc4967702be373ab47ea80d"

  # 插件进程环境注入（关于 BAO_TOKEN 配置，见 deployment.md）：
  env = [
    "BAO_ADDR=https://openbao.internal:8200",
    "BAO_TOKEN=<插件服务身份 token>",
  ]
}
```

随后即可直接通过 `bao secrets enable -path=acme openbao-plugin-secrets-acme` 启用（或由 OpenBao auto-register 自动挂载）。

---

## 下一步

安装完成后，请阅读 **[部署与 Token 设置](deployment.md)** 配置插件运行所需的服务身份 Token 与环境变量。
