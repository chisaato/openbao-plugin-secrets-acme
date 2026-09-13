# 升级指南 (Upgrade)

本插件自身**不存储、不迁移、不删除**你的数据——secrets mount 下的所有数据都保存在 OpenBao 的 storage（如 raft）中，插件升级（换二进制）本身不会动它。

但是 **OpenBao 的插件版本机制**有一个容易踩的坑：直接替换插件版本号会导致旧 mount 加载失败，表现为 **mount 下所有数据"消失"（路径 404 / 列表为空）**。数据其实还在，按本文 §3 的步骤即可恢复。

> **TL;DR：升级时不要直接替换 HCL 里的版本号。新旧版本必须短暂并存，把 mount `tune` 到新版本后，再移除旧版本。**

---

## 1. 机制：为什么会"丢"数据（OpenBao 官方行为）

以下均为 OpenBao ≥ 2.5 的官方设计行为（对 2.6.2 源码验证）：

1. **mount 默认被"钉死"在启用那一刻的具体插件版本**。`bao secrets enable` 时不填 `-plugin-version`，OpenBao 会自动 pin 到当时 catalog 中最新的具体版本（如 `v0.2.3`），之后**不会自动跟随新版本**。
2. **声明式注册会清理不再声明的旧版本**。`plugin_auto_register = true` 时，OpenBao 在 unseal / SIGHUP 时会把 config 中已声明、但 catalog 里存在而 config 里已删除的旧版本条目自动 deregister（日志：`removing plugin present in storage but no longer present in configuration`）。
3. **mount 找不到被 pin 的版本时会被跳过**。日志：
   ```
   failed to create mount entry ... plugin not found in the catalog, version=v0.2.3
   skipping plugin-based mount entry
   ```
   mount 不加载，所有请求 404。**底层数据 `logical/<mount-uuid>/` 不会被删除。**

典型事故链：把 HCL 里 plugin 块的 `version`/`sha256sum` 直接从 v0.2.3 改成 v0.3.0 → 重启 → 旧版本被自动 deregister → mount 找不到 v0.2.3 → 被 skip → "数据全丢了"。

> OpenBao 2.7.0 才引入 `plugin_version = latest`（mount 自动跟随最新版本）。2.5/2.6 上升级必须手动 `tune`。

## 2. 正确升级流程

核心原则：**旧版本块/二进制先保留，与新版本并存；mount 切换到新版本并验证后，才移除旧版本。**

### 2.1 方式 A：传统手动注册（`plugin_directory`）

本地插件的二进制**必须平铺在 `plugin_directory` 根目录**（子目录会被拒绝），多版本并存要靠**不同文件名**：

```text
/etc/openbao/plugins/
├── openbao-plugin-secrets-acme-v0.2.3   # 旧版本，保留
└── openbao-plugin-secrets-acme-v0.3.0   # 新版本
```

```sh
# 1. 注册新版本（注意 -command 指向新文件名）
sha256sum /etc/openbao/plugins/openbao-plugin-secrets-acme-v0.3.0
bao plugin register -sha256=<SHA256> -version=v0.3.0 \
  -command=openbao-plugin-secrets-acme-v0.3.0 secret openbao-plugin-secrets-acme

# 2. 将 mount 切换到新版本
bao secrets tune -plugin-version=v0.3.0 acme

# 3. 重载插件进程（多节点集群需在每个节点执行）
bao plugin reload -plugin=openbao-plugin-secrets-acme

# 4. 验证业务正常后，清理旧版本
bao plugin deregister -version=v0.2.3 secret openbao-plugin-secrets-acme
rm /etc/openbao/plugins/openbao-plugin-secrets-acme-v0.2.3
```

### 2.2 方式 B：声明式 `config-plugins`（OCI 拉取，OpenBao ≥ 2.5）

官方支持同一 `type` + `name` 声明多个不同 `version` 的块（OpenBao v2.6.2 文档原文："Blocks may share the same `type` and `name` but must have different a `version`. This allows for seamless upgrades of plugin versions."）：

```hcl
# 升级期间新旧两个块并存
plugin "secret" "openbao-plugin-secrets-acme" {
  image        = "ghcr.io/chisaato/openbao-plugin-secrets-acme"
  version      = "0.2.0"                       # 旧版本，先保留
  binary_name  = "openbao-plugin-secrets-acme"
  sha256sum    = "<v0.2.0 的 sha256sum>"
  env = [ /* ... */ ]
}

plugin "secret" "openbao-plugin-secrets-acme" {
  image        = "ghcr.io/chisaato/openbao-plugin-secrets-acme"
  version      = "0.3.0"                       # 新版本
  binary_name  = "openbao-plugin-secrets-acme"
  sha256sum    = "<v0.3.0 的 sha256sum>"
  env = [ /* ... */ ]
}
```

```sh
# 1. 重启 OpenBao（或 SIGHUP）→ 新版本自动注册（旧版本块仍在声明中，不会被清理）
# 2. 切换 mount 并重载
bao secrets tune -plugin-version=v0.3.0 acme
bao plugin reload -plugin=openbao-plugin-secrets-acme
# 3. 验证正常后，移除 v0.2.0 块，再次重启/SIGHUP（此时清理旧版本是安全的）
```

> **注意**：OCI 拉取模式下同一 `binary_name` 可以多版本并存；但**本地二进制声明式块**（不用 `image`，见 2.3）必须用不同 `command` 文件名，见下。

### 2.3 本地 compose 测试环境（`plugin_directory` + 声明式块）

与 compose.yaml / bao-config.hcl 配套的本地流程：

```sh
# 1. 准备两个版本的二进制（文件名带版本后缀，平铺在 data/plugins/ 下）
just build
cp bin/openbao-plugin-secrets-acme data/plugins/openbao-plugin-secrets-acme-v0.3.0
#    旧版本文件若已删除：git checkout v0.2.3 && just build 后同样复制改名

# 2. bao-config.hcl 中两个 plugin 块并存，command 各指向对应文件名
```

```hcl
plugin "secret" "acme" {
  command   = "openbao-plugin-secrets-acme-v0.2.3"   # 旧版本，先保留
  version   = "v0.2.3"
  sha256sum = "<旧 sha>"
  env = [ /* BAO_ADDR / BAO_TOKEN 不变 */ ]
}

plugin "secret" "acme" {
  command   = "openbao-plugin-secrets-acme-v0.3.0"   # 新版本
  version   = "v0.3.0"
  sha256sum = "<新 sha>"
  env = [ /* 同上 */ ]
}
```

```sh
# 3. 重启 → tune → 验证 → 移除旧块与旧文件 → 再重启
docker compose restart
bao secrets tune -plugin-version=v0.3.0 acme
# 验证业务正常后：
#   删除 v0.2.3 块 + data/plugins/openbao-plugin-secrets-acme-v0.2.3，再 restart
```

> 两个块的 `command` **不能**写同一个文件名——两个版本指向同一文件时，只有一个 `sha256sum` 能匹配，另一个版本启动时校验失败。

## 3. 事故恢复：升级后数据"消失"

**症状**：替换版本号并重启后，mount 路径 404 / 列表为空，OpenBao 日志出现：

```
failed to create mount entry ... plugin not found in the catalog, version=vX.Y.Z
skipping plugin-based mount entry
```

**判定**：数据大概率还在（`bao secrets list -detailed` 中 mount 条目仍在，`uuid` 未变，只是没加载）。

**抢救步骤**（在旧版本条目被清理后 30 分钟内……实际上任何时候都可以，只要没做 §5 的操作）：

1. 按本文 §2 把**旧版本**加回来（HCL 块 / 二进制 / `plugin register`，恢复到"新旧并存"状态）；
2. 重启 OpenBao（或 SIGHUP）→ mount 按原 UUID 恢复加载，数据应当全部回来；
3. 确认无误后，再走 §2 的正常升级流程。

**验证恢复**：

```sh
bao secrets list -detailed   # mount 存在，plugin_version 与 uuid 符合预期
bao plugin list -versioned   # 新旧版本都已注册
```

## 4. 事故恢复：升级后 mount 卡在 setup 只读（写请求全部 500）

**症状**：插件升级并重启后，mount **读操作正常**，但**任意写操作**（含本插件任何端点的写）返回：

```
Code: 500.
* cannot write to storage during setup
```

**原因**：OpenBao core 在 mount 构建/恢复期间会为该 mount 的 storage view 打上只读标记（`logical.ErrSetupReadOnly`，见 `sdk/logical/storage.go`），正常在 mount 加载完成后自动清除。升级过渡期（新旧版本并存、mount 尚未 `tune` 到新版本）或恢复流程异常（典型：catalog 注册的 `sha256sum` 与实际二进制不一致，插件加载失败导致恢复中止）时，标记残留，该 mount 的所有写请求被 core 拒绝。

**诊断**：

```sh
# 1. 服务端日志找插件加载/恢复报错（最直接）
journalctl -u bao | grep -iE "acme|plugin|setup|read.?only"
# docker: docker logs <container> 2>&1 | grep -iE "acme|plugin|setup"

# 2. 对比 catalog 注册的 sha 与磁盘二进制
bao plugin info openbao-plugin-secrets-acme
sha256sum /etc/openbao/plugins/openbao-plugin-secrets-acme-*
```

**恢复**：

1. 若 sha 不匹配：修正 `plugin register` / HCL 块的 `sha256sum`；
2. **重启 OpenBao 并 unseal**，让 mount 重新走完整恢复流程（in-process 插件必须重启进程才会重新加载，仅改注册不重启无效）；
3. 确认 `bao read sys/mounts/acme` 的 `running_version` 符合预期后，再做一次写操作验证；
4. 期间**不要** `secrets disable` 重挂（数据会丢）；确需 remount 用 `bao secrets move`（保留数据）。

> 排障期间读操作不受影响（只读标记只拦写），可放心用 `bao read` 验证数据完好。

## 5. 什么情况会**真正**丢数据

以下操作不可恢复，升级排障时**严禁**：

- **`bao secrets disable <mount>` 后重建**：官方文档明确 disabling existing mounts **will wipe the existing data**；且重建的 mount 会分配新 UUID，读的是全新空目录。
- **本地测试环境 `just init --reset`**：销毁 `data/data` 并重新 init，数据不可恢复。
- **更换/清空 raft 数据目录**（换卷、误删挂载路径）：存储回到"未初始化"状态，init 后是全新空库。

另：static seal 下不要随意更换 `current_key`——旧数据无法解密会导致 unseal 失败（数据未损坏，但需 key 轮换流程保留 `previous_key`）。

## 参考

- OpenBao 官方插件升级流程：<https://github.com/openbao/openbao/blob/main/website/content/docs/guides/upgrade/plugins.mdx>
- 声明式 plugin 块配置（多版本并存）：<https://github.com/openbao/openbao/blob/v2.6.2/website/content/docs/configuration/plugins.mdx>
- OpenBao 插件改进 RFC（mount pin 版本痛点、2.7 `latest`）：<https://github.com/openbao/openbao/blob/main/website/content/community/rfcs/plugin-improvements.mdx>
- 类似案例（mount skip / 404）：openbao/openbao#3478
