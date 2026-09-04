# 异步签发 Job 与 account 级证书复用 — 设计文档

日期：2026-09-05
状态：已与维护者确认的设计稿（待实施）

## 1. 背景与目标

当前 `POST certs/<role>` 同步阻塞完成整个 ACME DNS-01 流程（订单创建 → DNS
传播等待 → 挑战验证 → finalize → 取证书）。DNS 传播通常需数十秒到数分钟，
长于常规 API 超时；进程重启即丢失全部进行中的签发上下文。

目标：

1. 签发改为异步任务模式：提交即返回 `job_id`，由插件后台 Worker 维护状态；
   状态持久化，进程重启后能继续/收敛未完成任务。
2. 引入 account 级证书复用（SNI 覆盖去重）：已签发的泛域名证书直接服务
   同 account 下后续的单域名请求，减少对 LE 速率配额（按 account 计）的消耗。
3. 保留同步语义兼容（`sync=true`）。

## 2. 约束与边界（非目标）

- 不拆解 LEGO `client.Certificate.Obtain` 内部步骤、不持久化 ACME order URL。
  恢复的粒度是 Job 级：中断后重新驱动一次完整的 `Obtain`（幂等代价 = 多一次
  ACME 订单，LE 验证缓存使其实际成本很低）。Traefik 亦采用同级别的粗粒度策略。
- 不做多节点 CAS 抢锁（OpenBao 插件 Storage 无 CAS 语义）；竞态窗口与后果
  见 §9 已知限制。
- 失败的 Job 不自动重试；客户端可重新提交。
- OpenBao 插件响应无自定义 HTTP 状态码，异步提交返回 200 + `job_id`
  （非 202）。

## 3. 总体流程

```
POST certs/<role>
  ├─ validateNames（不变，先于一切复用判定）
  ├─ 精确缓存命中且未到期 → 同步返回证书（现状路径，不变）
  ├─ [新增] 覆盖复用命中（account 级，§5）→ 同步返回证书
  ├─ sync=true → 现状同步 singleflight 签发路径（不变）
  └─ 默认（异步）
      ├─ 已存在同 (role, domains) 的 pending/processing Job → 返回该 job_id
      ├─ 否则创建 Job（pending）→ 启动 Worker → 返回 job_id

Worker:
  processing → doIssue（现有签发链路，含路由/凭据/Obtain/KV 输出）
    ├─ 成功 → 缓存写入（Users=0）+ Job 快照 → completed
    └─ 失败 → 记录错误 → failed
```

缓存命中与覆盖复用始终同步返回证书（无论 sync 与否）——快速路径无需异步化。

## 4. 存储设计

### 4.1 Job 条目：`jobs/<job_id>`

```go
type jobStatus string

const (
    jobPending    jobStatus = "pending"
    jobProcessing jobStatus = "processing"
    jobCompleted  jobStatus = "completed"
    jobFailed     jobStatus = "failed"
)

type jobEntry struct {
    ID         string    `json:"id"`            // crypto/rand 16 字节 hex
    Role       string    `json:"role"`
    Account    string    `json:"account"`
    CN         string    `json:"common_name"`
    AltNames   []string  `json:"alt_names"`
    Domains    []string  `json:"domains"`       // CN + AltNames，提交时定死
    CacheKey   string    `json:"cache_key"`     // 提交时计算；信息性（GET jobs 展示/排查），Worker 完成路径自行重算
    Status     jobStatus `json:"status"`
    Error      string    `json:"error,omitempty"`
    CreatedAt  time.Time `json:"created_at"`
    UpdatedAt  time.Time `json:"updated_at"`

    // completed 时快照证书结果（与 cacheEntry 同源），保证缓存条目
    // 日后被淘汰/撤销后 GET jobs 仍可取回签发结果。
    Cert *jobCertSnapshot `json:"cert,omitempty"`
}

type jobCertSnapshot struct {
    CertificatePEM string `json:"certificate"`
    PrivateKeyPEM  string `json:"private_key"`
    IssuerCertPEM  string `json:"issuer_cert"`
    CertURL        string `json:"url"`
    CertStableURL  string `json:"cert_stable_url"`
    NotBefore      string `json:"not_before,omitempty"` // RFC3339
    NotAfter       string `json:"not_after,omitempty"`
    OutputPath     string `json:"output_path,omitempty"` // KV 输出位置
}
```

私钥/证书入 Job 条目与现有 `cache/` 条目同级别（storage barrier 加密保护），
无新增暴露面。

### 4.2 cacheEntry 增加来源字段

```go
type cacheEntry struct {
    // ...现有字段不变...
    Role string `json:"role,omitempty"` // 签发时的 role 名；覆盖复用匹配用
}
```

旧条目（无 `role` 字段）解码后 `Role == ""`：精确缓存路径不受影响；
覆盖复用扫描跳过 `Role == ""` 的条目（保守）。v0.1.0 预发布阶段无迁移负担。

## 5. 覆盖复用（account 级 SNI 去重）

### 5.1 触发位置与前置条件

`POST certs/<role>` 内、精确缓存查询之后执行。前置条件全部满足才启用：

- 请求 role 未设置 `disable_cache`（`disable_cache` 语义 = 不共享缓存，
  覆盖复用一并跳过）；
- 请求 role 未设置 `disable_cert_reuse`（新增 role 字段，默认 false）；
- `validateNames` 已通过（复用不绕过任何白名单语义）。

### 5.2 匹配算法

扫描 `List("cache/")`，对每个条目依次过滤：

1. `entry.Role != ""` 且 `entry.Account == 请求 role 的 account`
   （LE 限速按 account 计，故复用范围是 account 而非 role）；
2. 证书未到期：`!certNeedsRenewal(entry.CertificatePEM, 请求 role 的
   CacheForRatio)`（以请求 role 的新鲜度标准决定是否值得复用）；
3. 条目域名**覆盖**请求的全部域名（CN + SAN）。

覆盖判定 `covers(entryDomain, requestDomain)`：

| entry 域名 | 请求域名 | 结果 | 说明 |
|---|---|---|---|
| `*.example.com` | `sub.example.com` | ✅ | 通配符覆盖单层标签 |
| `*.example.com` | `example.com` | ❌ | 裸域不被泛域名覆盖 |
| `*.example.com` | `a.b.example.com` | ❌ | 多级子域不被覆盖（正确性边界） |
| `*.example.com` | `*.example.com` | ✅ | 精确相等 |
| `sub.example.com` | `sub.example.com` | ✅ | 精确相等 |

规则形式化：`e == d`，或（`e` 形如 `*.<zone>` 且 `d == <label>.<zone>`，
`label` 非空且不含 `.`）。只做"已有条目覆盖新请求"方向；反向（拿单域名
证书服务泛域名请求）不做。

多域名请求要求**同一单条目**覆盖全部域名，否则视为未命中。

### 5.3 命中行为

与现有精确缓存命中路径一致：`Users++`（`cacheUpdate` 单临界区读改写）、
`respondWithCert(freshIssue=false)`（不重写 KV 输出，`output_path` 指向
签发时写入位置；若签发 role 未配置 KV 输出则无 `output_path` 字段）、
正常建 lease。即：复用返回的证书与精确命中在 lease/续期/撤销语义上完全一致。

### 5.4 Job 阶段的去重

提交异步任务时，同 `(role, domains)` 精确匹配（域名集合相等，**顺序无关**，
与 `cacheKey` 的排序语义一致）的 `pending/processing` Job 直接挂靠返回其
`job_id`，不新建。

**已知限制**：不同 role、相同域名集合、并发提交（双双处于未完成态）时
仍会各签一次。跨 role 的重复消耗由完成后的覆盖复用兜底（稳态下第二个
role 的请求命中复用），并发窗口内的重复签发与现有单机 singleflight
（key 含 role）行为一致，可容忍。

## 6. API 定义

### 6.1 `POST certs/<role>`（修改）

新增字段：

- `sync`（bool，默认 false）：true 时保持 v0.1.0 同步行为与响应结构。
- 异步响应（200）：

```json
{
  "job_id": "a1b2c3...",
  "status": "pending",
  "common_name": "example.com",
  "domains": ["example.com"],
  "created_at": "2026-09-05T10:00:00Z",
  "poll_path": "jobs/a1b2c3..."
}
```

缓存命中/覆盖复用时无论 sync 与否均返回完整证书响应（现有结构，
含 lease），响应附 `reused: true` 以便调用方区分。

### 6.2 `GET jobs/<job_id>`

返回 Job 全量视图：`status`、`error`、提交信息（role/domains/时间戳）；
`completed` 时附证书快照（certificate/private_key/issuer_cert/url/
not_before/not_after/output_path）。Job 读取路径**不建 lease、无续期/撤销
生命周期**——lease 语义仍绑定在同步路径的签发响应上；需要 lease 管理的
调用方应使用 `sync=true`。

### 6.3 `GET jobs/`（LIST）

返回 `jobs/` 下的 job_id 列表（框架标准 list 语义）。

### 6.4 `DELETE jobs/<job_id>`

仅允许删除 `completed/failed` 的 Job；`pending/processing` 拒绝删除。

## 7. 异步完成路径的关键不变式

现有缓存不变式：`Users == 持有引用的 lease 数`（lease 撤销时减一并可能
删除条目、ACME revoke）。异步完成时**没有** lease 被创建，因此：

- Worker 成功后写缓存条目 `Users = 0`（而非 1）；
- 后续每次精确命中/覆盖复用照常 `Users++`，lease 撤销照常减一，
  不变式保持；
- `Users = 0` 的孤立条目留存至到期重签覆写或 lease 路径清理，与现有
  到期 miss 语义兼容（到期即视为 miss 落入重签）。

KV 输出：Worker 以插件服务身份（env `BAO_TOKEN`，与 `credLoader`/
`kvWriter`/`tokenRenewer` 同一身份，忽略请求级 ClientToken）调用现有
`writeCertOutput` 链路，按 Job 所属 role 的 `output_kv_mount` 写入。

## 8. 进程重启恢复

- 挂载点：`framework.Backend.InitializeFunc`（Factory 与 Backend 构造均
  设置；测试路径无人调用 `Initialize` 时零影响）。
- 流程：`List("jobs/")` → 解码 → 过滤 `pending/processing` → 逐个启动
  Worker 重新驱动（完整重新 `Obtain`，不恢复 ACME order）。
- 不做基于时长的失败判定：role/account/凭据若已失效，Worker 会自然失败
  并把错误写入 Job；避免引入额外超时参数。
- 本进程内以 running 集合（mutex 保护）防止同 Job 重复驱动。
- Worker 上下文使用独立的后台 context（不绑定任何 HTTP 请求生命周期）。

## 9. 已知限制（明确容忍）

1. 无多节点互斥：极端情况下两个插件进程可同时驱动同一 Job（后果 =
   最多多一次 ACME Obtain，Job 状态以最后写入为准收敛）。OpenBao 请求
   仅由 active 节点插件处理，常态单点执行。
2. 跨 role 相同域名并发提交可能双签（§5.4）。
3. 失败不自动重试；客户端重提。
4. completed/failed Job 永久留存直至 `DELETE`（或整个引擎数据重置）。

## 10. 文档更新

- `docs/local-testing.md`：签发段改为异步示例（提交 → 轮询 jobs → 取证），
  附 `sync=true` 兼容说明与 Job 管理（list/delete）示例。
- `README.md`：新增 `jobs/` API、`sync`/`disable_cert_reuse` 字段说明、
  复用语义（account 级、通配符单层覆盖边界）、异步路径无 lease 的说明。

## 11. 测试计划

1. `covers` 覆盖判定表驱动单测（含多级子域/裸域/泛域各边界）。
2. 覆盖复用：account 匹配、跨 account 不复用、`disable_cache`/
   `disable_cert_reuse` 跳过、到期不复用、命中后 `Users++` 与响应结构。
3. Job 状态机（注入 fake 签发函数，仿 `credLoader` 注入模式）：
   pending→processing→completed/failed、提交挂靠去重、DELETE 语义。
4. 恢复：预置 pending/processing 条目后调用 `Initialize`，断言 Worker
   重新驱动并收敛（fake 签发函数）。
5. 异步完成不变式：完成条目 `Users=0`；后续命中 `Users++`；无 lease 路径
   不误删条目。
6. Pebble 端到端（沿用现有 `pebble_test.go` harness）：异步提交 → 轮询至
   completed → 证书有效；单域请求命中先前泛域名签发（覆盖复用 e2e）。
7. 兼容：`sync=true` 响应结构与现有测试期望逐字段一致。
