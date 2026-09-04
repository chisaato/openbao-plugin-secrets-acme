# 异步签发 Job 与 account 级证书复用 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `POST certs/<role>` 默认异步返回 `job_id` 并由插件后台维护签发状态（持久化 + 重启恢复），同时引入 account 级证书覆盖复用（泛域名证书服务同 account 单域名请求）。

**Architecture:** 新增 `acme/jobs.go`（Job 存储模型/状态机/后台 Worker/jobs API 路径）与 `acme/reuse.go`（覆盖匹配纯函数 + account 级复用扫描）。签发核心提取为 `obtainCert`（可注入 fake），同步/异步两条路径共享。恢复挂在 `InitializeFunc`，Worker 生命周期挂在 Clean 链。

**Tech Stack:** Go 1.26、OpenBao sdk v2 framework、LEGO v5（`Obtain` 整体调用，不拆解）、testify、pebble/challtestsrv（e2e，缺失自动 Skip）。

**Spec:** `docs/superpowers/specs/2026-09-05-async-issuance-jobs-design.md`（本计划从 spec 论证，执行者须同时阅读）

## Global Constraints

- module `github.com/chisaato/openbao-plugin-secrets-acme`；Go 1.26
- **不新增第三方依赖**：job id 用 `crypto/rand`，并发原语用 `sync`
- 测试命令：`just test`（= `go test -race ./acme/...`）；收尾跑 `just vet && just fmt`
- 注释用中文、行内注释优先（AGENTS.md 约定）；用户可见错误/响应文案中文
- 单测不依赖外网；pebble 不在 PATH 时相关用例自动 Skip（`startPebble` 既有行为）
- **本仓库工作区存在大量与本计划无关的既有未提交改动：每次提交只 `git add` 本任务明确列出的文件**
- 现有单测中所有 `POST certs/<role>` 默认行为将从同步变异步；涉及「同步错误语义」的既有用例按各任务指示改加 `"sync": true`，禁止为迁就旧测试改变新默认行为

---

### Task 1: 覆盖匹配纯函数（reuse.go）

**Files:**
- Create: `acme/reuse.go`
- Test: `acme/reuse_test.go`

**Interfaces:**
- Produces: `wildcardCovers(pattern, domain string) bool`、`domainCovered(entryDomain, requestDomain string) bool`、`domainsCovered(entryDomains, requestDomains []string) bool`（Task 2/5/10 依赖）

- [ ] **Step 1: 写失败测试** `acme/reuse_test.go`

```go
package acme

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWildcardCovers(t *testing.T) {
	cases := []struct {
		pattern, domain string
		want            bool
	}{
		{"*.example.com", "sub.example.com", true},      // 单层标签覆盖
		{"*.example.com", "example.com", false},         // 裸域不被覆盖
		{"*.example.com", "a.b.example.com", false},     // 多级子域不被覆盖（正确性边界）
		{"*.example.com", "*.example.com", false},       // 泛域名不按通配匹配泛域名（仅精确相等走 domainCovered）
		{"sub.example.com", "sub.example.com", false},   // 非泛域 pattern 不是通配
		{"*", "x.example.com", false},                   // 空 zone 无效
		{"*.example.com", "SUB.EXAMPLE.COM", true},      // 大小写不敏感
	}
	for _, c := range cases {
		require.Equal(t, c.want, wildcardCovers(c.pattern, c.domain),
			"wildcardCovers(%q, %q)", c.pattern, c.domain)
	}
}

func TestDomainsCovered(t *testing.T) {
	require.True(t, domainsCovered([]string{"*.example.com"}, []string{"*.example.com"})) // 精确相等
	require.True(t, domainsCovered([]string{"a.com", "*.example.com"}, []string{"sub.example.com", "a.com"}))
	require.False(t, domainsCovered([]string{"*.example.com"}, []string{"example.com"}))
	require.False(t, domainsCovered([]string{"*.example.com"}, []string{"sub.example.com", "other.com"}))
	require.False(t, domainsCovered([]string{"*.example.com"}, nil)) // 空请求不成立
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -race ./acme/ -run 'TestWildcardCovers|TestDomainsCovered'`
Expected: FAIL（`undefined: wildcardCovers`）

- [ ] **Step 3: 最小实现** `acme/reuse.go`

```go
package acme

import "strings"

// wildcardCovers：pattern 形如 *.zone 时仅覆盖单层标签（label 非空且不含点）。
// 裸域与多级子域不被泛域名覆盖（spec §5.2 正确性边界）。大小写不敏感。
func wildcardCovers(pattern, domain string) bool {
	zone, ok := strings.CutPrefix(strings.ToLower(pattern), "*.")
	if !ok || zone == "" {
		return false
	}
	label, rest, found := strings.Cut(strings.ToLower(domain), ".")
	return found && rest == zone && label != ""
}

// domainCovered：精确相等，或单层通配覆盖。
func domainCovered(entryDomain, requestDomain string) bool {
	return strings.EqualFold(entryDomain, requestDomain) || wildcardCovers(entryDomain, requestDomain)
}

// domainsCovered：单个条目的域名集合须覆盖请求的全部域名（spec §5.2）。
func domainsCovered(entryDomains, requestDomains []string) bool {
	if len(requestDomains) == 0 {
		return false
	}
	for _, d := range requestDomains {
		ok := false
		for _, e := range entryDomains {
			if domainCovered(e, d) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: 运行确认通过**

Run: `go test -race ./acme/ -run 'TestWildcardCovers|TestDomainsCovered'`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add acme/reuse.go acme/reuse_test.go
git commit -m "feat: 覆盖匹配纯函数（泛域名单层覆盖/精确相等）"
```

---

### Task 2: cacheEntry.Role + findReusableEntry（account 级复用扫描）

**Files:**
- Modify: `acme/cache.go:20-31`（cacheEntry 结构体）
- Modify: `acme/reuse.go`（追加扫描函数）
- Test: `acme/reuse_test.go`（追加用例）

**Interfaces:**
- Consumes: Task 1 的 `domainsCovered`；既有 `certNeedsRenewal`（cache.go:134）、`storageKeyCache`（cache.go:18）
- Produces: `cacheEntry.Role string`（json `role,omitempty`）；`func (b *backend) findReusableEntry(ctx context.Context, s logical.Storage, role *roleEntry, domains []string) (*cacheEntry, string, error)`——返回 (条目, 缓存key, err)，未命中返回 (nil, "", nil)。依赖 Task 3 的 `roleEntry.DisableCertReuse` 字段

- [ ] **Step 1: 写失败测试**（追加到 `acme/reuse_test.go`）

```go
func TestFindReusableEntry(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()
	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, AllowSubdomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, role)

	// 同 account 其他 role 签发的泛域名条目（fresh，Users=0 模拟异步产物）
	wildRole := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	key := putFreshCacheEntry(t, b, ctx, storage, wildRole, []string{"*.example.com"})
	// putFreshCacheEntry 不写 Role——手工补上（模拟 Task 4 后的新签发）
	require.NoError(t, b.cacheUpdate(ctx, storage, key, func(e *cacheEntry) *cacheEntry {
		e.Role = "wild"
		return e
	}))

	// 命中：同 account 跨 role 的单层覆盖
	entry, k, err := b.findReusableEntry(ctx, storage, role, []string{"sub.example.com"})
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, key, k)

	// 裸域不覆盖 → 未命中
	entry, _, err = b.findReusableEntry(ctx, storage, role, []string{"example.com"})
	require.NoError(t, err)
	require.Nil(t, entry)

	// 多级子域不覆盖 → 未命中
	entry, _, err = b.findReusableEntry(ctx, storage, role, []string{"a.b.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry)

	// Role=="" 的旧条目跳过
	require.NoError(t, b.cacheUpdate(ctx, storage, key, func(e *cacheEntry) *cacheEntry {
		e.Role = ""
		return e
	}))
	entry, _, err = b.findReusableEntry(ctx, storage, role, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry)
}

func TestFindReusableEntryGuards(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()
	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, AllowSubdomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, role)

	// 跨 account 不复用
	otherAcct := &roleEntry{Account: "other", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	key := putFreshCacheEntry(t, b, ctx, storage, otherAcct, []string{"*.example.com"})
	require.NoError(t, b.cacheUpdate(ctx, storage, key, func(e *cacheEntry) *cacheEntry {
		e.Role = "wild"
		return e
	}))
	entry, _, err := b.findReusableEntry(ctx, storage, role, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry, "跨 account 不得复用")

	// 到期条目不复用
	stale := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, stale)
	staleKey := putFreshCacheEntry(t, b, ctx, storage, stale, []string{"sub.example.com"})
	require.NoError(t, b.cacheUpdate(ctx, storage, staleKey, func(e *cacheEntry) *cacheEntry {
		base := time.Now().UTC()
		e.Role = "wild"
		e.CertificatePEM = selfSignedCertFor(t, base.Add(-100*time.Hour), base.Add(-time.Hour)) // 已过期
		return e
	}))
	entry, _, err = b.findReusableEntry(ctx, storage, stale, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry, "到期条目不得复用")

	// disable_cache / disable_cert_reuse 直接短路
	dc := &roleEntry{Account: "le", DisableCache: true, CacheForRatio: 70}
	entry, _, err = b.findReusableEntry(ctx, storage, dc, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry, "disable_cache 不得复用")

	dr := &roleEntry{Account: "le", DisableCertReuse: true, CacheForRatio: 70}
	entry, _, err = b.findReusableEntry(ctx, storage, dr, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry, "disable_cert_reuse 不得复用")
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -race ./acme/ -run 'TestFindReusableEntry'`
Expected: FAIL（`entry.Role`/`DisableCertReuse`/`findReusableEntry` 未定义）

- [ ] **Step 3: 实现**

`acme/cache.go` 的 `cacheEntry` 追加字段（Issuers 行后）：

```go
	// Role：签发时的 role 名。覆盖复用按 account 匹配的前提（spec §4.2）；
	// 空值=旧条目，覆盖扫描跳过。
	Role string `json:"role,omitempty"`
```

`acme/reuse.go` 追加：

```go
// findReusableEntry：account 级覆盖复用扫描（spec §5）。过滤链：
// role 开关（disable_cache/disable_cert_reuse）→ 条目来源（Role 非空、
// 同 account）→ 新鲜度（按请求 role 的 CacheForRatio）→ 全域名覆盖。
// 未命中返回 (nil, "", nil)。
func (b *backend) findReusableEntry(ctx context.Context, s logical.Storage, role *roleEntry, domains []string) (*cacheEntry, string, error) {
	if role.DisableCache || role.DisableCertReuse {
		return nil, "", nil
	}
	keys, err := s.List(ctx, storageKeyCache)
	if err != nil {
		return nil, "", err
	}
	for _, k := range keys {
		item, err := s.Get(ctx, storageKeyCache+k)
		if err != nil {
			return nil, "", err
		}
		if item == nil {
			continue
		}
		var entry cacheEntry
		if err := item.DecodeJSON(&entry); err != nil {
			return nil, "", err
		}
		if entry.Role == "" || entry.Account != role.Account {
			continue
		}
		if certNeedsRenewal(entry.CertificatePEM, role.CacheForRatio) {
			continue
		}
		if !domainsCovered(entry.Domains, domains) {
			continue
		}
		return &entry, k, nil
	}
	return nil, "", nil
}
```

- [ ] **Step 4: 运行确认通过（全量，保证 struct 变更未破坏既有用例）**

Run: `just test`
Expected: PASS（pebble 缺失时相关用例 Skip）

- [ ] **Step 5: 提交**

```bash
git add acme/cache.go acme/reuse.go acme/reuse_test.go
git commit -m "feat: account 级覆盖复用扫描 findReusableEntry + cacheEntry.Role"
```

---

### Task 3: role 新字段 disable_cert_reuse

**Files:**
- Modify: `acme/path_roles.go:15-24`（roleEntry）、`:84-94`（fields）、`:111-120`（read 响应）、`:186-194` 附近（write）
- Test: `acme/path_roles_test.go`（追加用例）

**Interfaces:**
- Produces: `roleEntry.DisableCertReuse bool`（json `disable_cert_reuse`）；role read 响应新增 `disable_cert_reuse` 键

- [ ] **Step 1: 写失败测试**（追加到 `acme/path_roles_test.go`）

```go
func TestRoleDisableCertReuseField(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web", Storage: storage,
		Data: map[string]interface{}{
			"account":            "le",
			"allowed_domains":    "example.com",
			"disable_cert_reuse": true,
		},
	})
	require.NoError(t, err)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, true, resp.Data["disable_cert_reuse"])

	// 显式改回 false（GetOk 对显式 false 也返回 ok=true）
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/web", Storage: storage,
		Data: map[string]interface{}{"disable_cert_reuse": false},
	})
	require.NoError(t, err)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, false, resp.Data["disable_cert_reuse"])
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -race ./acme/ -run TestRoleDisableCertReuseField`
Expected: FAIL（`disable_cert_reuse` 字段不存在）

- [ ] **Step 3: 实现**（仿 `disable_cache` 的四处既有写法）

`roleEntry` 追加（`DisableCache` 行后）：

```go
	DisableCertReuse  bool     `json:"disable_cert_reuse"`
```

fields map 追加：

```go
		"disable_cert_reuse": {Type: framework.TypeBool, Description: "禁用 account 级证书覆盖复用（泛域名服务单域请求）。"},
```

read 响应 map 追加：

```go
						"disable_cert_reuse": role.DisableCertReuse,
```

`pathRoleWrite` 中 `disable_cache` 块后追加（沿用「显式出现才覆盖」惯例）：

```go
	if v, ok := d.GetOk("disable_cert_reuse"); ok {
		role.DisableCertReuse = v.(bool)
	}
```

- [ ] **Step 4: 运行确认通过**

Run: `go test -race ./acme/ -run TestRole`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add acme/path_roles.go acme/path_roles_test.go
git commit -m "feat: role 级 disable_cert_reuse 字段"
```

---

### Task 4: obtainCert 提取 + issueFn 注入点 + doIssue 写 Role

**Files:**
- Modify: `acme/path_certs.go:161-222`（doIssue 拆分）
- Modify: `acme/backend.go:60-73`（backend struct 增 issueFn 等字段）、`:34-49`（Backend 构造初始化）
- Test: `acme/path_certs_test.go`（追加 issueFn 注入用例）

**Interfaces:**
- Produces:
  - `func (b *backend) obtainCert(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error)`（含路由匹配校验、错误文案 `"ACME obtain: %w"`、`"路由"` 不变）
  - backend 字段 `issueFn func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error)`（nil=真实 Obtain；Task 6/9/10 的 fake 注入点）
  - doIssue 产生的 `cacheEntry` 带 `Role: roleName`
- 行为不变式：本任务后 `just test` 全绿（纯重构 + 字段补充），`TestIssuePathValidation` 的 `"路由"` 断言保持

- [ ] **Step 1: 写失败测试**（追加到 `acme/path_certs_test.go`）

```go
// TestDoIssueSetsRoleField：签发条目必须带来源 role（覆盖复用依赖，spec §4.2）。
func TestDoIssueSetsRoleField(t *testing.T) {
	b, storage, _ := setupObtainable(t)
	ctx := context.Background()

	// 注入 fake Obtain：绕开真实 ACME，仅验证 doIssue 的条目装配
	base := time.Now().UTC()
	b.issueFn = func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error) {
		return &certificate.Resource{
			Domains:           domains,
			PrivateKey:        []byte("K"),
			Certificate:       []byte(selfSignedCertFor(t, base.Add(-time.Hour), base.Add(24*time.Hour))),
			IssuerCertificate: []byte("I"),
		}, nil
	}

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web", Storage: storage,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"common_name": "example.com", "sync": true},
	})
	require.NoError(t, err)

	role, err := b.getRole(ctx, storage, "web")
	require.NoError(t, err)
	entry, err := b.cacheGet(ctx, storage, cacheKey(role, []string{"example.com"}))
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, "web", entry.Role)
}
```

（文件若未导入 `certificate`，补 `"github.com/go-acme/lego/v5/certificate"`。）

- [ ] **Step 2: 运行确认失败**

Run: `go test -race ./acme/ -run TestDoIssueSetsRoleField`
Expected: FAIL（`b.issueFn` 未定义）

- [ ] **Step 3: 实现**

`acme/backend.go` struct 追加字段（`issueGroup` 行后）：

```go
	// issueFn 非空时替代真实 ACME Obtain（仅测试注入，仿 credLoader 模式）。
	issueFn func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error)
	// jobMu/runningJobs：本进程内 job 单驱动防护（spec §8）。
	jobMu        sync.Mutex
	runningJobs  map[string]struct{}
	// jobCtx：后台 Worker 长生命周期上下文（startJobRunner 设置；nil 回退 Background）。
	jobCtx context.Context
```

`Backend()` 中 `b.RunningVersion = Version` 前追加：

```go
	b.runningJobs = make(map[string]struct{})
	// 重启恢复入口：Factory（生产）挂载后由 core 调用 Initialize；直接调用
	// Backend() 的单测路径无人调 Initialize，保持零影响（spec §8）。
	b.InitializeFunc = b.initializeBackend
```

（`backend.go` 需补 import `"github.com/go-acme/lego/v5/certificate"`。）

`acme/path_certs.go` 的 doIssue 改写为（路由/客户端/Obtain 全部移入 obtainCert）：

```go
// obtainCert：路由→实时凭据→provider→一次完整 ACME Obtain。issueFn 非空时
// （测试注入）直接替代；错误文案与同步路径历史行为一致。
func (b *backend) obtainCert(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error) {
	if b.issueFn != nil {
		return b.issueFn(ctx, req, account, domains)
	}
	router, extraOpts, err := b.buildRoutes(ctx, req, account)
	if err != nil {
		return nil, err
	}
	// 无任何路由（account 未配 dns_providers）或域无归属 → 明确报错
	for _, dom := range domains {
		if _, err := router.match(dom); err != nil {
			return nil, err
		}
	}

	user, err := account.legoUser()
	if err != nil {
		return nil, err
	}
	client, err := newLegoClient(user, account.ServerURL, account.InsecureTLS)
	if err != nil {
		return nil, err
	}
	var dns01Provider challenge.Provider = router
	// dns01Opts 生产为空（零行为差异），测试注入传播预检选项；dns-provider
	// 条目的 skip_propagation_check 经 buildRoutes 聚合为请求级选项。
	if err := client.Challenge.SetDNS01Provider(dns01Provider,
		append(append([]dns01.ChallengeOption{}, b.dns01Opts...), extraOpts...)...); err != nil {
		return nil, fmt.Errorf("设置 DNS-01 provider: %w", err)
	}

	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
		// lego v5 把证书密钥类型移到逐请求字段且无默认值（缺失时报
		// "the key type is missing"）；v1 未暴露 role 级 key_type，统一 EC256。
		KeyType: certcrypto.EC256,
	})
	if err != nil {
		return nil, fmt.Errorf("ACME obtain: %w", err)
	}
	return res, nil
}

// doIssue：obtainCert→缓存（Users=1 对应领导者 lease）→KV 输出→响应。
func (b *backend) doIssue(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, account *accountEntry, cn string, domains []string, key string) (*logical.Response, error) {
	res, err := b.obtainCert(ctx, req, account, domains)
	if err != nil {
		return nil, err
	}

	entry := &cacheEntry{
		Users:                1,
		Account:              account.Name,
		Role:                 roleName, // 覆盖复用的来源 role（spec §4.2）
		CN:                   cn,
		Domains:              domains,
		CertURL:              res.CertURL,
		CertStableURL:        res.CertStableURL,
		PrivateKeyPEM:        string(res.PrivateKey),
		CertificatePEM:       string(res.Certificate),
		IssuerCertificatePEM: string(res.IssuerCertificate),
	}
	// ↓↓↓ 以下与原 doIssue 尾段逐行相同，原样保留 ↓↓↓
	if !role.DisableCache {
		if err := b.cachePut(ctx, req.Storage, key, entry); err != nil {
			return nil, err
		}
	}
	return b.respondWithCert(ctx, req, roleName, role, entry, key, true)
}
```

（原 doIssue 中被移走的注释按语义随代码迁移。）

- [ ] **Step 4: 运行全量确认（新用例 + 回归）**

Run: `just test`
Expected: PASS（TestDoIssueSetsRoleField 走 pebble，缺失 Skip；其余既有用例全绿）

- [ ] **Step 5: 提交**

```bash
git add acme/backend.go acme/path_certs.go acme/path_certs_test.go
git commit -m "refactor: 提取 obtainCert 并注入 issueFn；签发条目记录来源 role"
```

---

### Task 5: POST certs 增 sync 字段 + reused 标记 + 覆盖复用分支

**Files:**
- Modify: `acme/path_certs.go:16-33`（fields）、`:77-159`（pathIssueCert）、`:224-263`（respondWithCert 签名）
- Test: `acme/path_certs_test.go`（追加用例；既有同步语义用例加 `"sync": true`）

**Interfaces:**
- Consumes: Task 2 `findReusableEntry`；既有 `cacheUpdate`/`respondWithCert`/`outputKVPath`
- Produces:
  - `POST certs/<role>` 请求字段 `sync`（bool，默认 false）
  - `respondWithCert(ctx, req, roleName, role, entry, key string, freshIssue bool, kvPathOverride string)`（新增末参；命中/新鲜路径传 `""`）
  - 缓存命中与覆盖复用响应附 `reused: true`
  - 覆盖复用路径的 `output_path` 以**签发 role** 为准（跨 role 复用时不得指向请求 role 名下未写入的路径）

- [ ] **Step 1: 更新既有同步语义测试**——以下用例的 `POST certs/*` 请求 Data 全部加 `"sync": true`（保持其验证的同步契约不变）：
  - `path_certs_test.go`：`TestIssuePathValidation`、`TestIssueWithFakeProvider`、`TestDisableCacheRoleSkipsCachePut`、`TestIssueSingleflightWaitersRefcount`（secret_cert_test.go 内的直接 HandleRequest 签发调用同理）
  - `secret_cert_test.go`：`TestRenewReissueWaitersRefcount` 中的签发请求

Run: `go test -race ./acme/`
Expected: 若不改仍全绿（说明这些用例恰走缓存命中或未达签发分支）；改动的意义在 Task 7 默认异步落地前先行锁定语义

- [ ] **Step 2: 写失败测试**（追加到 `acme/path_certs_test.go`）

```go
// TestIssueCoverageReuse：account 级泛域名条目同步服务单域请求（spec §5.3）。
func TestIssueCoverageReuse(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	issuerRole := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, AllowSubdomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	putRoleFixture(t, ctx, storage, issuerRole)
	// 以 issuerRole 的 roleJSON 算 key，条目模拟其泛域名签发产物
	wildRole := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	key := putFreshCacheEntry(t, b, ctx, storage, wildRole, []string{"*.example.com"})
	require.NoError(t, b.cacheUpdate(ctx, storage, key, func(e *cacheEntry) *cacheEntry {
		e.Role = "web"
		return e
	}))

	// 请求 role 与签发 role 不同名（cross-role），account 相同
	putRoleFixture(t, ctx, storage, &roleEntry{Account: "le", Name: "x",
		AllowedDomains: []string{"example.com"}, AllowSubdomains: true, CacheForRatio: 70})
```

（`putRoleFixture` 直写 `roles/web` 固定键——为支持第二 role，本步同时把 `putRoleFixture` 的键改为由 `role.Name` 决定、缺省 `"web"`，见 Step 4 附带改动。）

```go
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key: "accounts/le",
		Value: mustJSON(t, &accountEntry{
			Name: "le", ServerURL: "https://acme.test/dir", Contact: "admin@example.com",
		}),
	}))
	_ = issuerRole

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web2", Storage: storage,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"common_name": "sub.example.com"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "覆盖复用应同步成功: %v", resp)
	require.Equal(t, true, resp.Data["reused"])
	require.NotEmpty(t, resp.Data["certificate"])
	// output_path 以签发 role（web）为准，而非请求 role
	require.Equal(t, "certs/web/_wildcard.example.com", resp.Data["output_path"])

	entry, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.Equal(t, 2, entry.Users, "复用须 Users++")

	// role 开关：请求 role disable_cert_reuse → 不复用（落不到签发则报路由错）
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/noreuse", Storage: storage,
		Data: map[string]interface{}{
			"account": "le", "allowed_domains": "example.com",
			"allow_subdomains": true, "disable_cert_reuse": true,
		},
	})
	require.NoError(t, err)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/noreuse", Storage: storage,
		Data: map[string]interface{}{"common_name": "sub.example.com"},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError(), "disable_cert_reuse 应跳过复用")
}
```

（`roleEntry` 无 `Name` 字段——Step 4 中给 `putRoleFixture` 增加 name 参数或改签名 `putRoleFixtureAt(t, ctx, storage, name, role)`；测试按最终签名微调，断言不变。）

- [ ] **Step 3: 运行确认失败**

Run: `go test -race ./acme/ -run TestIssueCoverageReuse`
Expected: FAIL（`reused` 键不存在/请求 role 路由缺失前未走复用）

- [ ] **Step 4: 实现**

4a. `pathCerts` fields 追加：

```go
			"sync":              {Type: framework.TypeBool, Description: "同步等待签发完成（v0.1.0 兼容）。默认 false：异步返回 job_id。"},
```

4b. `respondWithCert` 签名追加末参并调整 kvPath 分支：

```go
func (b *backend) respondWithCert(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, entry *cacheEntry, key string, freshIssue bool, kvPathOverride string) (*logical.Response, error) {
```

```go
	} else if kvPathOverride != "" {
		// 覆盖复用：以签发 role 名下的既有 KV 数据为准（spec §5.3）
		kvPath = kvPathOverride
	} else if role.OutputKVMount != "" {
```

两处既有调用点各补末参 `""`。

4c. `pathIssueCert`：精确命中块（原 107-132 行）后插入复用分支，并给命中响应加 `reused`：

```go
	// 1.5) 覆盖复用：同 account 已签发证书覆盖全部请求域名 → 同步返回
	// （spec §5）。命中语义与精确命中一致：Users++、不重写 KV、正常建 lease。
	if reuseEntry, rkey, rerr := b.findReusableEntry(ctx, req.Storage, role, domains); rerr != nil {
		return nil, rerr
	} else if reuseEntry != nil {
		if uerr := b.cacheUpdate(ctx, req.Storage, rkey, func(e *cacheEntry) *cacheEntry {
			e.Users++
			return e
		}); uerr != nil {
			return nil, uerr
		}
		resp, rerr := b.respondWithCert(ctx, req, roleName, role, reuseEntry, rkey, false, b.reuseKVPath(ctx, req.Storage, roleName, role, reuseEntry))
		if rerr != nil {
			return logical.ErrorResponse("签发失败: %v", rerr), nil
		}
		resp.Data["reused"] = true
		return resp, nil
	}
```

精确命中分支的 `respondWithCert` 成功后补 `resp.Data["reused"] = true`。

4d. `reuseKVPath`（放 `acme/reuse.go`）：

```go
// reuseKVPath：复用响应的 output_path 指向签发时真实写入的位置。
// 跨 role 复用时按签发 role 的 output_kv_mount 解析；签发 role 已删除或
// 未配 KV 输出则省略 output_path（指向不存在的路径会误导调用方）。
func (b *backend) reuseKVPath(ctx context.Context, s logical.Storage, roleName string, role *roleEntry, entry *cacheEntry) string {
	if entry.Role != "" && entry.Role != roleName {
		issuer, err := b.getRole(ctx, s, entry.Role)
		if err != nil || issuer == nil || issuer.OutputKVMount == "" {
			return ""
		}
		return outputKVPath(entry.Role, entry.CN)
	}
	if role.OutputKVMount == "" {
		return ""
	}
	return outputKVPath(roleName, entry.CN)
}
```

4e. `putRoleFixture` 支持任意 role 名（保持旧调用兼容）：新增 `putRoleFixtureAt(t, ctx, storage, name, role)`，原函数委托它传 `"web"`；`TestIssueCoverageReuse` 用 `putRoleFixtureAt` 写 `roles/web2`（并删除测试里不适用的 `Name` 字段写法）。

- [ ] **Step 5: 运行确认通过（全量）**

Run: `just test`
Expected: PASS（新增用例绿；命中路径 reused=true 不破坏既有断言——它们不检查该键）

- [ ] **Step 6: 提交**

```bash
git add acme/path_certs.go acme/path_certs_test.go acme/reuse.go acme/secret_cert_test.go
git commit -m "feat: POST certs 覆盖复用分支 + reused 标记 + sync 字段（兼容开关）"
```

---

### Task 6: jobs 存储模型 + 状态机 + 后台 Worker（jobs.go）

**Files:**
- Create: `acme/jobs.go`
- Test: `acme/jobs_test.go`

**Interfaces:**
- Consumes: Task 4 `obtainCert`/`issueFn`；既有 `cachePut`/`cacheDelete`/`writeCertOutput`/`cacheKey`/`getRole`/`getAccount`/`jobTryStart` 系（本任务实现）
- Produces（Task 7/8/9 依赖）:
  - `jobStatus`（`jobPending/jobProcessing/jobCompleted/jobFailed`）、`jobEntry`、`jobCertSnapshot`、`storageKeyJobs = "jobs/"`
  - `func newJobID() (string, error)`（crypto/rand 16 字节 hex）
  - `func (b *backend) jobUpdate(ctx, st logical.Storage, job *jobEntry) error`（刷新 UpdatedAt 后落盘）
  - `func (b *backend) jobTryStart(id string) bool` / `jobFinish(id string)`
  - `func (b *backend) runJob(ctx context.Context, st logical.Storage, job *jobEntry)`
  - `func (b *backend) findActiveJob(ctx context.Context, st logical.Storage, roleName string, domains []string) (*jobEntry, error)`（同 role + 域名集合顺序无关相等 + pending/processing）
  - `func (b *backend) jobResponse(job *jobEntry) *logical.Response`（提交/挂靠响应：job_id/status/common_name/domains/created_at/poll_path[/error]）
  - `func (b *backend) workerCtx() context.Context`
  - `func (b *backend) submitJob(ctx, req, roleName string, role *roleEntry, cn string, domains []string) (*logical.Response, error)`

- [ ] **Step 1: 写失败测试** `acme/jobs_test.go`

```go
package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// stubIssueFn 生成固定有效期的 fake 签发结果。
func stubIssueFn(t *testing.T) func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error) {
	base := time.Now().UTC()
	return func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error) {
		return &certificate.Resource{
			Domains:           domains,
			PrivateKey:        []byte("K"),
			Certificate:       []byte(selfSignedCertFor(t, base.Add(-time.Hour), base.Add(24*time.Hour))),
			IssuerCertificate: []byte("I"),
			CertURL:           "https://acme.test/cert/1",
		}, nil
	}
}

// jobFixture：role/account 齐备 + fake issueFn，供状态机测试。
func jobFixture(t *testing.T) (*backend, logical.Storage, context.Context) {
	t.Helper()
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()
	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, AllowSubdomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, role)
	b.issueFn = stubIssueFn(t)
	return b, storage, ctx
}

// waitForJob：轮询至终态（completed/failed）并返回。
func waitForJob(t *testing.T, b *backend, st logical.Storage, id string) *jobEntry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		item, err := st.Get(context.Background(), storageKeyJobs+id)
		require.NoError(t, err)
		if item != nil {
			var job jobEntry
			require.NoError(t, item.DecodeJSON(&job))
			if job.Status == jobCompleted || job.Status == jobFailed {
				return &job
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s 未在限时内到达终态", id)
	return nil
}

func TestRunJobCompletes(t *testing.T) {
	b, storage, ctx := jobFixture(t)
	role, err := b.getRole(ctx, storage, "web")
	require.NoError(t, err)
	domains := []string{"example.com"}
	job := &jobEntry{ID: "job1", Role: "web", Account: role.Account, CN: domains[0],
		Domains: domains, CacheKey: cacheKey(role, domains), Status: jobPending,
		CreatedAt: time.Now().UTC()}
	require.NoError(t, b.jobUpdate(ctx, storage, job))

	b.runJob(ctx, storage, job)

	done := waitForJob(t, b, storage, "job1")
	require.Equal(t, jobCompleted, done.Status)
	require.Empty(t, done.Error)
	require.NotEmpty(t, done.Cert.CertificatePEM)
	require.Equal(t, "https://acme.test/cert/1", done.Cert.CertURL)
	require.NotEmpty(t, done.Cert.NotAfter)

	// 不变式（spec §7）：异步完成 Users=0
	entry, err := b.cacheGet(ctx, storage, done.CacheKey)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, 0, entry.Users)
	require.Equal(t, "web", entry.Role)
}

func TestRunJobFailure(t *testing.T) {
	b, storage, ctx := jobFixture(t)
	b.issueFn = func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error) {
		return nil, errors.New("boom")
	}
	role, err := b.getRole(ctx, storage, "web")
	require.NoError(t, err)
	job := &jobEntry{ID: "job2", Role: "web", Account: role.Account, CN: "example.com",
		Domains: []string{"example.com"}, Status: jobPending, CreatedAt: time.Now().UTC()}
	require.NoError(t, b.jobUpdate(ctx, storage, job))

	b.runJob(ctx, storage, job)
	done := waitForJob(t, b, storage, "job2")
	require.Equal(t, jobFailed, done.Status)
	require.Contains(t, done.Error, "boom")
	// 失败不落缓存
	n, err := b.cacheCount(ctx, storage)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}

func TestRunJobMissingRole(t *testing.T) {
	b, storage, ctx := jobFixture(t)
	job := &jobEntry{ID: "job3", Role: "gone", Account: "le", CN: "example.com",
		Domains: []string{"example.com"}, Status: jobPending, CreatedAt: time.Now().UTC()}
	require.NoError(t, b.jobUpdate(ctx, storage, job))

	b.runJob(ctx, storage, job)
	done := waitForJob(t, b, storage, "job3")
	require.Equal(t, jobFailed, done.Status)
	require.Contains(t, done.Error, "已不存在")
}

func TestRunJobKVFailureMirrorsSyncInvariant(t *testing.T) {
	b, storage, ctx := jobFixture(t)
	b.kvWriter = &failingKVWriter{err: errors.New("kv unavailable")}
	// role 补配 KV 输出
	putRoleFixture(t, ctx, storage, &roleEntry{Account: "le",
		AllowedDomains: []string{"example.com"}, AllowBareDomains: true,
		CacheForRatio: 70, OutputKVMount: "kv-certs"})
	role, _ := b.getRole(ctx, storage, "web")
	job := &jobEntry{ID: "job4", Role: "web", Account: role.Account, CN: "example.com",
		Domains: []string{"example.com"}, Status: jobPending, CreatedAt: time.Now().UTC()}
	require.NoError(t, b.jobUpdate(ctx, storage, job))

	b.runJob(ctx, storage, job)
	done := waitForJob(t, b, storage, "job4")
	require.Equal(t, jobFailed, done.Status)
	require.Contains(t, done.Error, "KV 输出失败")
	// 镜像同步路径不变式：KV 失败不留孤儿条目（spec §7/§9）
	entry, err := b.cacheGet(ctx, storage, cacheKey(role, []string{"example.com"}))
	require.NoError(t, err)
	require.Nil(t, entry)
}

func TestSubmitJobDedup(t *testing.T) {
	b, storage, ctx := jobFixture(t)
	// 阻塞 issueFn 以制造 pending 窗口
	release := make(chan struct{})
	b.issueFn = func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error) {
		<-release
		return stubIssueFn(t)(ctx, req, account, domains)
	}
	role, _ := b.getRole(ctx, storage, "web")
	resp, err := b.submitJob(ctx, &logical.Request{Storage: storage}, "web", role, "example.com", []string{"example.com"})
	require.NoError(t, err)
	require.Equal(t, "pending", resp.Data["status"])
	first := resp.Data["job_id"].(string)
	require.Equal(t, "jobs/"+first, resp.Data["poll_path"])

	// 同 (role, domains) 挂靠；域名顺序无关
	resp2, err := b.submitJob(ctx, &logical.Request{Storage: storage}, "web", role, "example.com", []string{"example.com"})
	require.NoError(t, err)
	require.Equal(t, first, resp2.Data["job_id"], "重复提交应挂靠同一 job")

	close(release)
	done := waitForJob(t, b, storage, first)
	require.Equal(t, jobCompleted, done.Status)
}

func TestJobTryStartSingleDrive(t *testing.T) {
	b, _, _ := jobFixture(t)
	require.True(t, b.jobTryStart("x"))
	require.False(t, b.jobTryStart("x"), "同 id 不得二次驱动")
	b.jobFinish("x")
	require.True(t, b.jobTryStart("x"))
}
```

（jobs_test.go 需 import `"github.com/go-acme/lego/v5/certificate"`。）

- [ ] **Step 2: 运行确认失败**

Run: `go test -race ./acme/ -run 'TestRunJob|TestSubmitJob|TestJobTryStart'`
Expected: FAIL（jobEntry 等未定义）

- [ ] **Step 3: 实现** `acme/jobs.go`

```go
package acme

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyJobs = "jobs/"

type jobStatus string

const (
	jobPending    jobStatus = "pending"
	jobProcessing jobStatus = "processing"
	jobCompleted  jobStatus = "completed"
	jobFailed     jobStatus = "failed"
)

// jobEntry：异步签发任务（spec §4.1）。私钥/证书快照与 cache/ 条目同级别
// （storage barrier 加密），无新增暴露面。
type jobEntry struct {
	ID        string           `json:"id"`
	Role      string           `json:"role"`
	Account   string           `json:"account"`
	CN        string           `json:"common_name"`
	AltNames  []string         `json:"alt_names"`
	Domains   []string         `json:"domains"`
	CacheKey  string           `json:"cache_key"` // 信息性（GET jobs 展示/排查），Worker 完成路径自行重算
	Status    jobStatus        `json:"status"`
	Error     string           `json:"error,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
	Cert      *jobCertSnapshot `json:"cert,omitempty"`
}

// jobCertSnapshot：completed 时的结果快照；缓存条目被淘汰/撤销后 GET jobs
// 仍可取回（spec §4.1）。
type jobCertSnapshot struct {
	CertificatePEM string `json:"certificate"`
	PrivateKeyPEM  string `json:"private_key"`
	IssuerCertPEM  string `json:"issuer_cert"`
	CertURL        string `json:"url"`
	CertStableURL  string `json:"cert_stable_url"`
	NotBefore      string `json:"not_before,omitempty"`
	NotAfter       string `json:"not_after,omitempty"`
	OutputPath     string `json:"output_path,omitempty"`
}

// newJobID：crypto/rand 16 字节 hex（无外部依赖）。
func newJobID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成 job id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func (b *backend) jobUpdate(ctx context.Context, st logical.Storage, job *jobEntry) error {
	job.UpdatedAt = time.Now().UTC()
	item, err := logical.StorageEntryJSON(storageKeyJobs+job.ID, job)
	if err != nil {
		return err
	}
	return st.Put(ctx, item)
}

// jobTryStart/jobFinish：本进程内同 job 单驱动（spec §8/§9；跨进程以
// storage 状态为准，重复驱动的后果是幂等的多一次 Obtain）。
func (b *backend) jobTryStart(id string) bool {
	b.jobMu.Lock()
	defer b.jobMu.Unlock()
	if _, ok := b.runningJobs[id]; ok {
		return false
	}
	b.runningJobs[id] = struct{}{}
	return true
}

func (b *backend) jobFinish(id string) {
	b.jobMu.Lock()
	defer b.jobMu.Unlock()
	delete(b.runningJobs, id)
}

// workerCtx：submit 路径 Worker 的长生命周期上下文；runner 未启动（单测
// 直接 HandleRequest）时回退 Background（进程退出即终止，可接受）。
func (b *backend) workerCtx() context.Context {
	if b.jobCtx != nil {
		return b.jobCtx
	}
	return context.Background()
}

// runJob：驱动单个 job 至终态（spec §3/§7）。无自动重试；失败终态由客户端
// 重提。KV 输出以插件服务身份执行（kvWriter 忽略 ClientToken）。
func (b *backend) runJob(ctx context.Context, st logical.Storage, job *jobEntry) {
	if !b.jobTryStart(job.ID) {
		return
	}
	defer b.jobFinish(job.ID)

	fail := func(format string, args ...interface{}) {
		job.Status = jobFailed
		job.Error = fmt.Sprintf(format, args...)
		_ = b.jobUpdate(ctx, st, job)
	}

	job.Status = jobProcessing
	if err := b.jobUpdate(ctx, st, job); err != nil {
		return // storage 不可写：留在原状态，重启恢复再驱动
	}

	role, err := b.getRole(ctx, st, job.Role)
	if err != nil {
		fail("读取 role: %v", err)
		return
	}
	if role == nil {
		fail("role %q 已不存在", job.Role)
		return
	}
	account, err := b.getAccount(ctx, st, role.Account)
	if err != nil {
		fail("读取 account: %v", err)
		return
	}
	if account == nil {
		fail("account %q 已不存在", role.Account)
		return
	}

	res, err := b.obtainCert(ctx, &logical.Request{Storage: st}, account, job.Domains)
	if err != nil {
		fail("签发失败: %v", err)
		return
	}

	key := cacheKey(role, job.Domains) // 以驱动时的 role 现值计算
	entry := &cacheEntry{
		// 不变式（spec §7）：异步完成无 lease 持引用 → Users=0；
		// 后续每次精确命中/覆盖复用再 Users++。
		Users:                0,
		Account:              account.Name,
		Role:                 job.Role,
		CN:                   job.CN,
		Domains:              job.Domains,
		CertURL:              res.CertURL,
		CertStableURL:        res.CertStableURL,
		PrivateKeyPEM:        string(res.PrivateKey),
		CertificatePEM:       string(res.Certificate),
		IssuerCertificatePEM: string(res.IssuerCertificate),
	}
	if !role.DisableCache {
		if err := b.cachePut(ctx, st, key, entry); err != nil {
			fail("写缓存: %v", err)
			return
		}
	}
	kvPath, err := b.writeCertOutput(ctx, &logical.Request{Storage: st}, job.Role, role, entry.CN, entry)
	if err != nil {
		// 镜像同步路径不变式：KV 失败不留孤儿条目。
		if !role.DisableCache {
			_ = b.cacheDelete(ctx, st, key)
		}
		fail("KV 输出失败: %v", err)
		return
	}

	job.Status = jobCompleted
	job.CacheKey = key
	job.Cert = &jobCertSnapshot{
		CertificatePEM: entry.CertificatePEM,
		PrivateKeyPEM:  entry.PrivateKeyPEM,
		IssuerCertPEM:  entry.IssuerCertificatePEM,
		CertURL:        entry.CertURL,
		CertStableURL:  entry.CertStableURL,
		OutputPath:     kvPath,
	}
	if nb, na := certValidity(entry.CertificatePEM); !na.IsZero() {
		job.Cert.NotBefore = nb.Format(time.RFC3339)
		job.Cert.NotAfter = na.Format(time.RFC3339)
	}
	if err := b.jobUpdate(ctx, st, job); err != nil {
		// 结果已入缓存/KV；快照写失败仅影响 GET jobs 可见性，下次重启
		// 扫描时该 job 仍为 processing，会被重新驱动一次（幂等）。
		_ = err
	}
}

// sameDomainSet：域名集合相等（顺序无关，与 cacheKey 排序语义一致）。
func sameDomainSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if !strings.EqualFold(sa[i], sb[i]) {
			return false
		}
	}
	return true
}

// findActiveJob：同 role + 域名集合的 pending/processing job（spec §5.4）。
func (b *backend) findActiveJob(ctx context.Context, st logical.Storage, roleName string, domains []string) (*jobEntry, error) {
	keys, err := st.List(ctx, storageKeyJobs)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		item, err := st.Get(ctx, storageKeyJobs+k)
		if err != nil {
			return nil, err
		}
		if item == nil {
			continue
		}
		var job jobEntry
		if err := item.DecodeJSON(&job); err != nil {
			return nil, err
		}
		if (job.Status == jobPending || job.Status == jobProcessing) &&
			job.Role == roleName && sameDomainSet(job.Domains, domains) {
			return &job, nil
		}
	}
	return nil, nil
}

// jobResponse：提交/挂靠响应（200 + job_id；OpenBao 插件无自定义状态码，
// 非 202——spec §2）。
func (b *backend) jobResponse(job *jobEntry) *logical.Response {
	data := map[string]interface{}{
		"job_id":      job.ID,
		"status":      string(job.Status),
		"common_name": job.CN,
		"domains":     job.Domains,
		"created_at":  job.CreatedAt.Format(time.RFC3339),
		"poll_path":   "jobs/" + job.ID,
	}
	if job.Error != "" {
		data["error"] = job.Error
	}
	return &logical.Response{Data: data}
}

// submitJob：去重挂靠或创建 job 并启动 Worker（spec §3/§5.4）。
func (b *backend) submitJob(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, cn string, domains []string) (*logical.Response, error) {
	existing, err := b.findActiveJob(ctx, req.Storage, roleName, domains)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return b.jobResponse(existing), nil
	}
	id, err := newJobID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	job := &jobEntry{
		ID: id, Role: roleName, Account: role.Account,
		CN: cn, AltNames: domains[1:], Domains: domains,
		CacheKey: cacheKey(role, domains),
		Status:   jobPending, CreatedAt: now, UpdatedAt: now,
	}
	if err := b.jobUpdate(ctx, req.Storage, job); err != nil {
		return nil, err
	}
	go b.runJob(b.workerCtx(), req.Storage, job)
	return b.jobResponse(job), nil
}
```

（import 需补 `"sort"`、`"strings"`。）

- [ ] **Step 4: 运行确认通过**

Run: `go test -race ./acme/ -run 'TestRunJob|TestSubmitJob|TestJobTryStart'`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add acme/jobs.go acme/jobs_test.go
git commit -m "feat: 异步签发 job 存储模型、状态机与后台 Worker"
```

---

### Task 7: pathIssueCert 接入异步默认路径

**Files:**
- Modify: `acme/path_certs.go:77-159`（pathIssueCert：sync 解析 + async 分支）
- Test: `acme/path_certs_test.go`（追加用例）

**Interfaces:**
- Consumes: Task 5（sync 字段已解析）、Task 6 `submitJob`
- Produces: `POST certs/<role>` 默认（无 `sync`）返回 job 提交响应；`sync=true` 走原 singleflight 同步路径

- [ ] **Step 1: 写失败测试**（追加到 `acme/path_certs_test.go`）

```go
// TestIssueAsyncDefault：默认异步返回 job_id，Worker 后台完成（spec §3/§6.1）。
func TestIssueAsyncDefault(t *testing.T) {
	b, storage, ctx := jobFixture(t)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web", Storage: storage,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"common_name": "example.com"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "异步提交应成功: %v", resp)
	require.NotEmpty(t, resp.Data["job_id"])
	require.Equal(t, "pending", resp.Data["status"])
	require.Nil(t, resp.Secret, "异步提交响应不得建 lease")

	jobID := resp.Data["job_id"].(string)
	done := waitForJob(t, b, storage, jobID)
	require.Equal(t, jobCompleted, done.Status)
}

// TestIssueSyncTrueCompat：sync=true 保留 v0.1.0 同步契约（含 lease）。
func TestIssueSyncTrueCompat(t *testing.T) {
	b, storage, ctx := jobFixture(t)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web", Storage: storage,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"common_name": "example.com", "sync": true},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "同步签发应成功: %v", resp)
	require.NotEmpty(t, resp.Data["certificate"])
	require.NotNil(t, resp.Secret, "同步响应须建 lease")
	require.Empty(t, resp.Data["job_id"])
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -race ./acme/ -run 'TestIssueAsyncDefault|TestIssueSyncTrueCompat'`
Expected: FAIL（默认仍同步：TestIssueAsyncDefault 断言 job_id 失败）

- [ ] **Step 3: 实现**——`pathIssueCert` 中覆盖复用分支之后、singleflight 之前插入：

```go
	// 2) 默认异步：挂靠同 (role, domains) 的未完成 job，或创建新 job 由
	//    后台 Worker 驱动（spec §3）。validateNames/account 校验已前置完成。
	if !d.Get("sync").(bool) {
		return b.submitJob(ctx, req, roleName, role, cn, domains)
	}

	// 3) sync=true：v0.1.0 同步契约，singleflight 防并发同 key 重复签发。
	//    （原注释保留）
```

（后续 singleflight 段原样保留，编号注释无需改动语义。）

- [ ] **Step 4: 运行全量确认**

Run: `just test`
Expected: PASS——若 `TestIssuePathValidation` 等既有用例失败，说明 Step 1（Task 5）漏改了某个请求的 `"sync": true`，补齐后重跑

- [ ] **Step 5: 提交**

```bash
git add acme/path_certs.go acme/path_certs_test.go
git commit -m "feat: POST certs 默认异步提交 job，sync=true 保留同步契约"
```

---

### Task 8: jobs API 路径（GET / LIST / DELETE）

**Files:**
- Create: `acme/path_jobs.go`
- Modify: `acme/backend.go:52-57`（paths() 注册）
- Test: `acme/path_jobs_test.go`

**Interfaces:**
- Consumes: Task 6 的 jobEntry/jobUpdate/storageKeyJobs
- Produces: `acme/jobs/<id>`（Read/Delete）、`acme/jobs/`（List）；`func pathJobs(b *backend) []*framework.Path`
- DELETE 语义：仅 completed/failed 可删（spec §6.4）

- [ ] **Step 1: 写失败测试** `acme/path_jobs_test.go`

```go
package acme

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func seedJob(t *testing.T, b *backend, ctx context.Context, storage logical.Storage, id string, status jobStatus) *jobEntry {
	t.Helper()
	job := &jobEntry{ID: id, Role: "web", Account: "le", CN: "example.com",
		Domains: []string{"example.com"}, Status: status, CreatedAt: time.Now().UTC()}
	// completed 预置快照
	if status == jobCompleted {
		job.Cert = &jobCertSnapshot{CertificatePEM: "CERT", PrivateKeyPEM: "KEY",
			CertURL: "https://acme.test/cert/1", NotAfter: "2026-09-06T00:00:00Z"}
	}
	require.NoError(t, b.jobUpdate(ctx, storage, job))
	return job
}

func TestJobReadCompleted(t *testing.T) {
	b, storage, ctx := jobFixture(t)
	seedJob(t, b, ctx, storage, "j-done", jobCompleted)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "jobs/j-done", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, "completed", resp.Data["status"])
	require.Equal(t, "CERT", resp.Data["certificate"])
	require.Equal(t, "KEY", resp.Data["private_key"])
	require.Equal(t, "https://acme.test/cert/1", resp.Data["url"])

	// 不存在的 job → nil, nil（404 语义由 core 呈现）
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "jobs/nope", Storage: storage,
	})
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestJobListAndDelete(t *testing.T) {
	b, storage, ctx := jobFixture(t)
	seedJob(t, b, ctx, storage, "j1", jobCompleted)
	seedJob(t, b, ctx, storage, "j2", jobFailed)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "jobs/", Storage: storage,
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"j1", "j2"}, resp.Data["keys"])

	// processing 拒绝删除
	seedJob(t, b, ctx, storage, "j3", jobProcessing)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "jobs/j3", Storage: storage,
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "未完成")

	// completed/failed 可删
	for _, id := range []string{"j1", "j2"} {
		_, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.DeleteOperation, Path: "jobs/" + id, Storage: storage,
		})
		require.NoError(t, err)
		item, err := storage.Get(ctx, storageKeyJobs+id)
		require.NoError(t, err)
		require.Nil(t, item)
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -race ./acme/ -run 'TestJobRead|TestJobList'`
Expected: FAIL（路径未注册，HandleRequest 无路由）

- [ ] **Step 3: 实现** `acme/path_jobs.go`，并在 `paths()` 追加 `paths = append(paths, pathJobs(b)...)`：

```go
package acme

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathJobs(b *backend) []*framework.Path {
	entry := &framework.Path{
		Pattern: "jobs/" + framework.GenericNameRegex("id"),
		Fields: map[string]*framework.FieldSchema{
			"id": {Type: framework.TypeString, Description: "job id（POST certs 返回的 job_id）。"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathJobRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathJobDelete},
		},
	}
	list := &framework.Path{
		Pattern: "jobs/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					keys, err := req.Storage.List(ctx, storageKeyJobs)
					if err != nil {
						return nil, err
					}
					return logical.ListResponse(keys), nil
				},
			},
		},
	}
	return []*framework.Path{entry, list}
}

// pathJobRead：job 全量视图；completed 时平铺证书快照（键名与同步签发响应
// 一致，spec §6.2）。读取不建 lease——lease 生命周期仅绑定同步路径响应。
func (b *backend) pathJobRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	item, err := req.Storage.Get(ctx, storageKeyJobs+d.Get("id").(string))
	if err != nil || item == nil {
		return nil, err
	}
	var job jobEntry
	if err := item.DecodeJSON(&job); err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		"job_id":      job.ID,
		"status":      string(job.Status),
		"role":        job.Role,
		"account":     job.Account,
		"common_name": job.CN,
		"alt_names":   job.AltNames,
		"domains":     job.Domains,
		"created_at":  job.CreatedAt.Format(time.RFC3339),
		"updated_at":  job.UpdatedAt.Format(time.RFC3339),
	}
	if job.Error != "" {
		data["error"] = job.Error
	}
	if c := job.Cert; c != nil {
		data["certificate"] = c.CertificatePEM
		data["private_key"] = c.PrivateKeyPEM
		data["issuer_cert"] = c.IssuerCertPEM
		data["url"] = c.CertURL
		data["cert_stable_url"] = c.CertStableURL
		if c.NotBefore != "" {
			data["not_before"] = c.NotBefore
		}
		if c.NotAfter != "" {
			data["not_after"] = c.NotAfter
		}
		if c.OutputPath != "" {
			data["output_path"] = c.OutputPath
		}
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathJobDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	item, err := req.Storage.Get(ctx, storageKeyJobs+id)
	if err != nil || item == nil {
		return nil, err
	}
	var job jobEntry
	if err := item.DecodeJSON(&job); err != nil {
		return nil, err
	}
	if job.Status == jobPending || job.Status == jobProcessing {
		return logical.ErrorResponse("job %s 未完成（%s），拒绝删除", id, job.Status), nil
	}
	return nil, req.Storage.Delete(ctx, storageKeyJobs+id)
}
```

（import 补 `"time"`。）

- [ ] **Step 4: 运行确认通过（全量）**

Run: `just test`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add acme/path_jobs.go acme/path_jobs_test.go acme/backend.go
git commit -m "feat: jobs API（GET/LIST/DELETE，未完成任务拒绝删除）"
```

---

### Task 9: 重启恢复（InitializeFunc + startJobRunner + Clean 链）

**Files:**
- Modify: `acme/jobs.go`（追加 initializeBackend/startJobRunner/resumeJobs）
- Modify: `acme/backend.go`（Factory 调用点确认——InitializeFunc 已在 Task 4 设置，Factory 无需再改；核对 Clean 链）
- Test: `acme/jobs_test.go`（追加用例）

**Interfaces:**
- Consumes: Task 4 已设置的 `b.InitializeFunc = b.initializeBackend`；`startTokenRenewer` 已占用 `b.Clean`（tokenrenew.go:211）
- Produces: `func (b *backend) initializeBackend(ctx context.Context, req *logical.InitializationRequest) error`、`func (b *backend) startJobRunner(st logical.Storage)`
- 关键点：**Clean 链式包装**——先取 `prev := b.Clean`（renewer 的），包装后调用，不得覆盖

- [ ] **Step 1: 写失败测试**（追加到 `acme/jobs_test.go`）

```go
// TestResumeJobsOnInitialize：pending/processing job 在 Initialize 时被重新
// 驱动至终态；completed/failed 不受影响（spec §8）。
func TestResumeJobsOnInitialize(t *testing.T) {
	b, storage, ctx := jobFixture(t)
	role, _ := b.getRole(ctx, storage, "web")

	// 预置：pending（可收敛）、processing（可收敛）、completed（不动）、failed（不动）
	for _, tc := range []struct{ id string; st jobStatus }{
		{"r-pending", jobPending}, {"r-processing", jobProcessing},
		{"r-done", jobCompleted}, {"r-failed", jobFailed},
	} {
		seedJob(t, b, ctx, storage, tc.id, tc.st)
	}
	// r-done 的快照保持原样：completed job 不得被重新驱动（快照 cert 不变即可断言）
	_ = role

	require.NoError(t, b.initializeBackend(ctx, &logical.InitializationRequest{Storage: storage}))

	for _, id := range []string{"r-pending", "r-processing"} {
		done := waitForJob(t, b, storage, id)
		require.Equal(t, jobCompleted, done.Status, "job %s 应恢复收敛", id)
	}
	done, err := storage.Get(ctx, storageKeyJobs+"r-done")
	require.NoError(t, err)
	var j jobEntry
	require.NoError(t, done.DecodeJSON(&j))
	require.Equal(t, "CERT", j.Cert.CertificatePEM, "completed 不得被重驱动")
	unchanged, err := storage.Get(ctx, storageKeyJobs+"r-failed")
	require.NoError(t, err)
	var jf jobEntry
	require.NoError(t, unchanged.DecodeJSON(&jf))
	require.Equal(t, jobFailed, jf.Status)

	// Clean 链：取消 jobCtx 不影响 renewer 的 prev Clean（此处仅验证包装可调用）
	require.NotNil(t, b.Clean)
	b.Clean(ctx)
}
```

- [ ] **Step 2: 运行确认失败**

Run: `go test -race ./acme/ -run TestResumeJobsOnInitialize`
Expected: FAIL（`initializeBackend` 未定义）

- [ ] **Step 3: 实现**（`acme/jobs.go` 追加）

```go
// initializeBackend：挂载/重启（unseal 后 backend 重建）时恢复未完成 job
// （spec §8）。role/account 若已被删除，Worker 自然失败并落错误信息。
func (b *backend) initializeBackend(ctx context.Context, req *logical.InitializationRequest) error {
	b.startJobRunner(req.Storage)
	return nil
}

// startJobRunner：创建长生命周期 ctx 并链式挂接 Clean（renewer 已占用
// b.Clean，不得覆盖——先取 prev 再包装，卸载时两级都执行）。
func (b *backend) startJobRunner(st logical.Storage) {
	prev := b.Clean
	ctx, cancel := context.WithCancel(context.Background())
	b.jobCtx = ctx
	b.Clean = func(c context.Context) {
		cancel()
		if prev != nil {
			prev(c)
		}
	}
	go b.resumeJobs(ctx, st)
}

// resumeJobs：扫描 jobs/ 并重新驱动全部未完成任务（完整重新 Obtain，
// 不恢复 ACME order——spec §2/§8）。不做时长判定：失效配置由 Worker
// 自然失败暴露。
func (b *backend) resumeJobs(ctx context.Context, st logical.Storage) {
	logger := b.Logger()
	keys, err := st.List(ctx, storageKeyJobs)
	if err != nil {
		logger.Warn("job 恢复扫描失败", "error", err)
		return
	}
	for _, k := range keys {
		if ctx.Err() != nil {
			return
		}
		item, err := st.Get(ctx, storageKeyJobs+k)
		if err != nil || item == nil {
			continue
		}
		var job jobEntry
		if err := item.DecodeJSON(&job); err != nil {
			logger.Warn("job 条目解码失败，跳过", "key", k, "error", err)
			continue
		}
		if job.Status != jobPending && job.Status != jobProcessing {
			continue
		}
		logger.Info("恢复未完成签发任务", "job_id", job.ID, "role", job.Role)
		go b.runJob(ctx, st, &job)
	}
}
```

- [ ] **Step 4: 运行确认通过（全量 + race）**

Run: `just test`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add acme/jobs.go acme/jobs_test.go
git commit -m "feat: Initialize 恢复未完成签发 job（Clean 链式挂接）"
```

---

### Task 10: Pebble 端到端（异步生命周期 + 覆盖复用）

**Files:**
- Test: `acme/jobs_test.go`（追加 e2e 用例，复用 `setupObtainable`）

**Interfaces:**
- Consumes: `setupObtainable`（secret_cert_test.go:228，pebble 缺失自动 Skip）、全部前序任务产物

- [ ] **Step 1: 写端到端用例**（追加到 `acme/jobs_test.go`）

```go
// TestE2EAsyncIssuanceAndReuse（pebble，缺失 Skip）：异步提交→轮询→取证；
// 泛域名签发后单域请求覆盖复用（spec §5 端到端）。
func TestE2EAsyncIssuanceAndReuse(t *testing.T) {
	b, storage, env := setupObtainable(t)
	ctx := context.Background()
	_ = env

	// 1) 异步签发 *.example.com
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web", Storage: storage,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"common_name": "*.example.com"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "异步提交应成功: %v", resp)
	jobID := resp.Data["job_id"].(string)

	done := waitForJob(t, b, storage, jobID)
	require.Equal(t, jobCompleted, done.Status, "error: %s", done.Error)
	require.NotEmpty(t, done.Cert.CertificatePEM)

	// 2) 同 account 单域请求 → 覆盖复用（同步返回，不新建 job）
	resp2, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web", Storage: storage,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"common_name": "sub.example.com"},
	})
	require.NoError(t, err)
	require.False(t, resp2.IsError(), "覆盖复用应成功: %v", resp2)
	require.Equal(t, true, resp2.Data["reused"])
	require.Equal(t, string(done.Cert.CertificatePEM), resp2.Data["certificate"],
		"复用返回的应正是泛域名证书")

	// 3) sync=true 单域请求：复用先行，同样命中（sync 只影响未命中时的行为）
	resp3, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web", Storage: storage,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"common_name": "other.example.com", "sync": true},
	})
	require.NoError(t, err)
	require.False(t, resp3.IsError())
	require.Equal(t, true, resp3.Data["reused"])
}
```

- [ ] **Step 2: 运行（本机有 pebble 则验证，无则 Skip）**

Run: `go test -race ./acme/ -run TestE2EAsyncIssuanceAndReuse -v`
Expected: PASS 或 SKIP（`pebble 不在 PATH`）

- [ ] **Step 3: 提交**

```bash
git add acme/jobs_test.go
git commit -m "test: 异步签发与覆盖复用 pebble 端到端"
```

---

### Task 11: 文档更新 + 全量验证收尾

**Files:**
- Modify: `docs/local-testing.md`（「配置测试资源」段末尾的签发示例，约 84-90 行）
- Modify: `README.md`（API 参考新增 jobs 段、role/请求新字段、复用语义）
- Modify: `test/acceptance_test.go:433,451`（验收测试的签发调用加 `"sync": true` 保持原语义断言）

- [ ] **Step 1: 更新 `docs/local-testing.md` 签发段**——把原「签发」curl 块替换为：

````markdown
# 签发（默认异步：立即返回 job_id，插件后台完成 DNS01 + 签发）
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X POST \
  -d '{"common_name":"example.com"}' \
  $BAO_ADDR/v1/acme/certs/web | python3 -m json.tool
# → {"job_id":"...","status":"pending","poll_path":"jobs/...",...}

# 轮询任务状态；completed 时响应含 certificate/private_key/issuer_cert/
# not_before/not_after/output_path（无 lease，不参与续期/撤销生命周期）
curl -s -H "X-Vault-Token: $BAO_TOKEN" \
  $BAO_ADDR/v1/acme/jobs/<job_id> | python3 -m json.tool

# 列出 / 清理任务
curl -s -H "X-Vault-Token: $BAO_TOKEN" $BAO_ADDR/v1/acme/jobs/ | python3 -m json.tool
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X DELETE $BAO_ADDR/v1/acme/jobs/<job_id>

# 旧同步行为（阻塞至签发完成、响应带 lease，可用于快速验证）
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X POST \
  -d '{"common_name":"example.com","sync":true}' \
  $BAO_ADDR/v1/acme/certs/web | python3 -m json.tool
````

（保留其后「字段含义…见 README.md」一段。）

- [ ] **Step 2: 更新 `README.md`**——追加/修改以下内容（并入现有 API 参考结构，不新开大章）：
  1. `POST certs/<role>`：`sync` 字段说明（默认 false 异步返回 `job_id`）；缓存命中/覆盖复用时仍同步返回证书且带 `reused: true`
  2. 新增 `GET jobs/<id>` / `GET jobs/` / `DELETE jobs/<id>`：字段表 + 「completed/failed 才可删」「异步路径证书无 lease」两点
  3. role 字段表新增 `disable_cert_reuse`（默认 false）
  4. 复用语义小节：同 account 范围（LE 限速按 account 计）；`*.zone` 仅覆盖单层标签、裸域与多级子域不复用；命中即 Users++ 并建 lease
  5. 运维注意：插件重启（unseal/重启）自动恢复 `pending/processing` 任务；失败的 job 不自动重试

- [ ] **Step 3: 验收测试兼容**——`test/acceptance_test.go` 两处 `client.Logical().Write("acme/certs/web", ...)` 的 data 加 `"sync": true`（保留其 lease/KV 断言语义）

Run: `cd test && go test -v -timeout 15m ./...`（`just testacc`）
Expected: PASS 或环境缺失 Skip

- [ ] **Step 4: 全量验证**

```bash
just fmt && just vet && just test
```
Expected: fmt 无 diff、vet 无告警、test 全绿

- [ ] **Step 5: 人工验证重启恢复（本机 compose 环境，`docs/local-testing.md` 前置步骤完成后）**

```bash
# 提交一个异步 job（用真实 staging CA 或 pebble）
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X POST -d '{"common_name":"example.com"}' \
  $BAO_ADDR/v1/acme/certs/web
# 立即重启（job 尚未完成时）
docker compose restart
# 轮询 job：应从 processing/pending 收敛到 completed（验证 Initialize 恢复真实生效）
curl -s -H "X-Vault-Token: $BAO_TOKEN" $BAO_ADDR/v1/acme/jobs/<job_id>
```
Expected: 重启后 job 被重新驱动并最终 `completed`。**若重启后 job 停留在原状态**，说明该 OpenBao 版本未在每次加载时调用 `Initialize`——降级方案：在 `pathCerts` 的 `pathIssueCert` 入口追加一次性惰性恢复（`sync.Once` 语义，扫描并启动 Worker），重跑本步骤。

- [ ] **Step 6: 提交**

```bash
git add docs/local-testing.md README.md test/acceptance_test.go
git commit -m "docs: 异步签发/轮询与覆盖复用文档；验收测试锁定 sync 语义"
```

---

## Self-Review 记录

- **Spec 覆盖**：§3 流程→T4/5/7；§4 存储→T2/6；§5 复用→T1/2/3/5；§6 API→T5/7/8/11；§7 不变式→T6（Users=0/KV 失败镜像）；§8 恢复→T4(InitializeFunc 设置)+T9；§9 限制→T6 注释/README；§10 文档→T11；§11 测试→各任务 + T10 e2e。无缺口。
- **占位符**：无 TBD/TODO；所有代码块完整可落地。
- **类型一致性**：`findReusableEntry`/`submitJob`/`runJob`/`jobUpdate`/`respondWithCert`（+`kvPathOverride`）/`obtainCert`/`issueFn` 签名在各任务间已对齐；`putRoleFixtureAt` 仅在 T5 内定义并使用。
- **已知风险**：T9 依赖 OpenBao 每次 backend 加载调用 `Initialize`——T11 Step 5 人工验证兜底，降级方案已内联。
