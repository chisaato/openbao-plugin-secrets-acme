# 架构设计与高级机制 (Architecture & Concepts)

本文档详细说明 `openbao-plugin-secrets-acme` 的内部设计原理，包括凭据解耦模型、ACL 安全矩阵、证书多级缓存、引用计数 Lease 机制与账户级证书复用。

---

## 1. 凭据解耦模型 (Credentials Decoupling)

- **实时拉取，不存明文快照**：
  在注册 `dns-providers` 时，存储层仅持久化 `credentials_ref`（即 OpenBao 内部的 KV 挂载点与相对路径）。当签发任务启动时，插件以自身的服务身份 Token 实时拉取 KV 数据。
  > **收益**：云厂商 API Token 轮换只需更新对应 KV 路径即可立即生效，无须更新插件配置或重启进程。

- **灵活的字段映射（显式 keys + 同名回退）**：
  如果 KV 中的 Key 名与 lego 预期的环境变量名不一致，可通过 `credentials_keys` 指定映射（JSON 对象字符串，键为 lego 环境变量名，值为用户 KV 中的键名）：
  ```sh
  bao write acme/dns-providers/cloudflare-primary \
    type=cloudflare \
    credentials_mount=secret \
    credentials_path=dns/cloudflare \
    credentials_kv_version=2 \
    credentials_keys='{"CLOUDFLARE_DNS_API_TOKEN":"cf_token"}'
  ```
  映射逻辑：先在 `credentials_keys` 中寻找匹配的目标 Key，如果未声明则在 KV 数据中回退查找与 lego 环境变量**同名**的 Key。支持 KVv1 和 KVv2（默认版本为 2），亦可通过 `credentials_version` 参数锁定指定历史版本（`0` 表示最新）。

- **Fail-fast 校验**：
  在写入 `dns-providers` 时，插件会立即发起试读并尝试初始化 Provider 配置；若配置缺失或格式非法，立即报错拒绝写入。凭据仅存在于一次签发请求的内存生命周期内，不写入磁盘、不打入日志、不在 API 返回。

---

## 2. ACL 安全访问控制矩阵

插件实行严格的职责与权限隔离机制：

| 身份角色 | 涉及路径 | 权限能力 | 详细说明 |
| --- | --- | --- | --- |
| **普通签发调用者** | `acme/certs/*`<br>`acme/jobs/*` | `create`<br>`update`<br>`read`<br>`delete`<br>`list` | 发起证书签发与轮询 Job 结果；**完全无需任何 KV 存储权限** |
| **普通签发调用者** | 其余 `acme/*` | 无 | 阻止普通应用直接访问 Provider、Account、Role 及缓存等管理入口 |
| **插件自身服务身份**<br>(`BAO_TOKEN`) | 凭据 KV 路径<br>(如 `secret/data/dns/*`) | `read` | 签发时实时读取用于 DNS01 挑战的云厂商 API 密钥 |
| **插件自身服务身份** | 输出 KV 路径<br>(如 `certs/data/*`) | `create`<br>`update` | 当配置了 `output_kv_mount` 时将证书同步输出 |
| **安全管理员** | `acme/*` 全局 | `*` | 管理 DNS Provider、ACME 账户、Role 与清空缓存 |
| **安全管理员**<br>(严格收紧) | `acme/accounts/*/key` | `read` (限制) | 导出 ACME 账户私钥 PEM 具有极高风险，建议严控 |

### 签发调用者最小 Policy 示例

```hcl
path "acme/certs/*" {
  capabilities = ["create", "update"]
}

path "acme/jobs/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

---

## 3. 证书缓存与 Lease 驱动的生命周期

### 共享缓存机制
- 针对相同 Role 和完全一致的域名集合（域名排序无关），多次签发将共享同一个持久化缓存条目。
- 签发时若指定 `disable_cache=true`，则会绕过缓存强制向 ACME CA 提交新订单。

### 基于比例的过期重签 (`cache_for_ratio`)
- 默认比例为 `70%`。
- 逻辑：$\text{剩余时间} < \text{证书总寿命} \times \text{cache\_for\_ratio}\%$ 时，此证书被判定为陈旧（stale）。
- 当客户端调用同步签发或执行 Lease Renew 时，若检测到证书陈旧，将自动沿用原 Role/Account 重新执行挑战签发，并同时刷新缓存与 KV 输出；若尚未进入陈旧期，则仅仅延长 Lease 有效期。

### 引用计数撤销 (Reference-counted Revoke)
- 每一个同步签发响应返回的 Lease 都会在缓存条目中增加一个引用计数（`users`）。
- 当调用者撤销或提前结束 Lease 时，引用计数减 1。
- **只有当引用计数清零时**，插件才会向 ACME 权威 CA 发送真实的吊销请求并移除缓存。有效避免由于某个客户端单方面撤销导致共享相同证书的其他微服务瘫痪。
- **清空缓存注意 (`bao delete acme/cache`)**：若管理员手动清空了缓存，随后现存 Lease 的撤销将因找不到条目而无法触发 ACME CA 真实吊销，仅完成本地资源回收。

### 自动续签器 (Auto-Renewer)
- 插件在挂载/重启后启动后台扫描循环（与异步 Job Worker 共享生命周期），默认每 **1 小时**扫描一次证书缓存：对每条条目按其签发 Role 的 `cache_for_ratio` 判定新鲜度，剩余寿命占比低于阈值的证书**自动向 CA 重签**（完整 DNS-01 流程），成功后原位覆写缓存条目并刷新 KV 输出（`output_kv_status` 回到 `written`）。
- **引用计数不变式**：后台续签不创建 Lease，也不改变条目的 `users` 计数——续签在单写临界区内原位替换证书字段，已持有 Lease 的消费方续期/撤销时计数保持对账。重签经由与同步签发/Lease 续期相同的 singleflight 合并，同 key 并发请求共享同一次 Obtain。
- **KV 投影失败不破坏缓存**：输出冲突/读取失败按既有 BestEffort 语义置 `skipped_conflict`/`skipped_error` 并保持"最后成功写入位置"；仅写入网络失败置 `skipped_error` 待下轮重试。后台续签**绝不删除缓存条目**（与同步签发路径 KV 硬失败删条目重试的语义相反——删除会连带丢掉 Lease 仍引用的证书）。
- **逃生口**：
  - `BAO_ACME_AUTORENEW_DISABLE=1`：完全关闭自动续签（外部 cron 驱动 `bao-acme cert renew` 时使用）。
  - `BAO_ACME_AUTORENEW_INTERVAL=30m`：自定义扫描间隔（Go duration 格式，默认 `1h`）。

---

## 4. 账户级证书复用 (Account-level Certificate Reuse)

Let's Encrypt 等权威 CA 实施了严格的速率配额限制（按 Account 统计订单与重复签发限制）。为了最大化节省配额并缩短响应时间：

- 在为某 Account 提交新证书订单前，插件会自动检索该 Account 已经签发且尚未到期的证书。
- **单标签通配符覆盖匹配**：
  - 如果已有证书能够完整覆盖本次请求的所有域名，则直接命中复用。
  - 例如已有 `*.example.com` 证书：
    - 可以复用覆盖：`api.example.com`, `web.example.com`, `*.example.com`。
    - **不能**复用覆盖：裸域 `example.com` 或三级子域 `a.b.example.com`（将按正常流程发起全新签发）。
- 命中复用后，直接同步返回该证书内容，Lease 引用计数加 1，并在响应中标记 `reused: true`。
- 若特定 Role 不希望参与复用，可在配置中声明 `disable_cert_reuse=true`。
