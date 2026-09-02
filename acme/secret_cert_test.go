package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// leaseReq 构造模拟 core 续期/撤销回调的请求。framework 会把签发响应的
// Secret（含 InternalData）复制进 lease 并在回调时回填 req.Secret，单测
// 直接手工构造等价形态。
func leaseReq(storage logical.Storage, key string) *logical.Request {
	return &logical.Request{
		Storage: storage,
		// 与真实 core 一致：续期/撤销回调携带 lease 持有者的 token（重签
		// 路径的凭据读取与 KV 输出需要）。
		ClientToken: "test-token",
		Secret: &logical.Secret{InternalData: map[string]interface{}{
			"cache_key": key,
			"role":      "web",
			"account":   "le",
		}},
	}
}

// seedCacheEntry 以指定有效期种入 Users=users 的缓存条目（绕过 ACME 交互），
// 返回与 InternalData 一致的 cache_key。
func seedCacheEntry(t *testing.T, b *backend, ctx context.Context, storage logical.Storage, notBefore, notAfter time.Time, users int) string {
	t.Helper()
	role := &roleEntry{Account: "le"}
	entry := &cacheEntry{
		Users: users, Account: "le", CN: "example.com", Domains: []string{"example.com"},
		CertificatePEM: selfSignedCertFor(t, notBefore, notAfter),
	}
	key := cacheKey(role, []string{"example.com"})
	require.NoError(t, b.cachePut(ctx, storage, key, entry))
	return key
}

// TestRevokeRefcount：撤销回调的引用计数语义——递减；>0 只存回（不真撤销、
// 不删条目）；归零删除整条（并向 ACME 服务端尽力真撤销）。
func TestRevokeRefcount(t *testing.T) {
	b, storage, _, _ := setupIssuable(t)
	ctx := context.Background()

	base := time.Now()
	key := seedCacheEntry(t, b, ctx, storage, base.Add(-time.Hour), base.Add(99*time.Hour), 2)

	// Users 2→1：仅递减存回，条目仍在
	resp, err := b.certRevoke(ctx, leaseReq(storage, key), nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	entry, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, 1, entry.Users)

	// Users 1→0：删除整条缓存
	resp, err = b.certRevoke(ctx, leaseReq(storage, key), nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	entry, err = b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.Nil(t, entry)
}

// TestRevokeMissingEntryGraceful：条目已被清理（cache DELETE / 命中路径 KV
// 失败连带删除 / 他人撤销归零）时，撤销必须优雅返回——不 panic、不误报。
func TestRevokeMissingEntryGraceful(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	resp, err := b.certRevoke(ctx, leaseReq(storage, "deadbeef"), nil)
	require.NoError(t, err)
	require.Nil(t, resp)
}

// TestRenewFreshCertNoop：证书仍新鲜（剩余寿命 > ratio）→ 空响应，由 core
// 自动续 lease；证书与引用计数均不动。
func TestRenewFreshCertNoop(t *testing.T) {
	b, storage, _, _ := setupIssuable(t)
	ctx := context.Background()

	base := time.Now()
	key := seedCacheEntry(t, b, ctx, storage, base.Add(-time.Hour), base.Add(99*time.Hour), 1)

	resp, err := b.certRenew(ctx, leaseReq(storage, key), nil)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())
	// 空响应（无 Data）→ framework 自动续 lease
	require.Nil(t, resp.Data)

	// 新鲜路径不得触碰缓存
	entry, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, 1, entry.Users)
}

// TestRenewMissingEntryAutoRenew：条目不存在时续期须优雅降级为空响应
// （自动续至自然到期），不得报错或尝试重签。
func TestRenewMissingEntryAutoRenew(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	resp, err := b.certRenew(ctx, leaseReq(storage, "deadbeef"), nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Data)
}

// TestRenewStaleCertReissues：已过期证书 → 任何 ratio 都需重签。测试环境
// 无真实 DNS（account 未配 dns_providers，路由即缺失），doIssue 必然报错
// ——错误本身证明走到了重签路径而非空响应降级。
func TestRenewStaleCertReissues(t *testing.T) {
	b, storage, _, _ := setupIssuable(t)
	ctx := context.Background()

	base := time.Now()
	key := seedCacheEntry(t, b, ctx, storage, base.Add(-100*time.Hour), base.Add(-time.Hour), 1)

	_, err := b.certRenew(ctx, leaseReq(storage, key), nil)
	require.Error(t, err)
}

// TestIssueSecretTypeAndInternal：签发/命中响应必须携带 acme_cert 类型的
// Secret，InternalData 含 Renew/Revoke 定位所需的 role/account/cache_key。
func TestIssueSecretTypeAndInternal(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, role)
	key := putFreshCacheEntry(t, b, ctx, storage, role, []string{"example.com"})

	resp, err := b.HandleRequest(ctx, issueRequest(ctx, storage))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "缓存命中应成功: %v", resp)

	// sdk v2.6.2 的 logical.Secret 无 Type 字段；framework 依据 InternalData
	// 的 secret_type 路由 Renew/Revoke 到已注册的 framework.Secret。
	require.Equal(t, secretCertType, resp.Secret.InternalData["secret_type"])
	// core 依响应的 Renewable 建 lease，缺失则 lease 不可续、certRenew 永不触发。
	require.True(t, resp.Secret.Renewable)
	require.Equal(t, key, resp.Secret.InternalData["cache_key"])
	require.Equal(t, "le", resp.Secret.InternalData["account"])
	require.Equal(t, "web", resp.Secret.InternalData["role"])
}

// TestBackendRegistersCertSecret：Backend() 必须注册证书 secret 类型，
// 否则 framework 不会为签发响应建立 lease，Renew/Revoke 回调无从触发。
func TestBackendRegistersCertSecret(t *testing.T) {
	b, err := Backend(logical.TestBackendConfig())
	require.NoError(t, err)
	require.Len(t, b.Secrets, 1)
	require.Equal(t, secretCertType, b.Secrets[0].Type)
}

// ---- 真实 Obtain 成功路径：challtestsrv 测试 provider ----
// registry/envNames 是包级白名单，测试进程内注册 challtestsrv 类型：
// Present/CleanUp 经管理 API 直写 TXT，配合 dns01Opts 跳过传播预检，
// doIssue 的真实 ACME Obtain（pebble）即可在单测内成功。

type challtestsrvProvider struct{ mgmtURL string }

func (p *challtestsrvProvider) Present(ctx context.Context, domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return p.postTxt("/set-txt", strings.TrimSuffix(info.EffectiveFQDN, "."), info.Value)
}

func (p *challtestsrvProvider) CleanUp(ctx context.Context, domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return p.postTxt("/clear-txt", strings.TrimSuffix(info.EffectiveFQDN, "."), "")
}

func (p *challtestsrvProvider) postTxt(endpoint, host, value string) error {
	body, err := json.Marshal(map[string]string{"host": host, "value": value})
	if err != nil {
		return err
	}
	resp, err := http.Post(p.mgmtURL+endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: HTTP %d", endpoint, resp.StatusCode)
	}
	return nil
}

// registerChalltestsrvProvider 注册测试 provider 类型，测试结束后还原白名单。
func registerChalltestsrvProvider(t *testing.T) {
	t.Helper()
	oldBuild, hadBuild := registry["challtestsrv"]
	oldNames := envNames["challtestsrv"]
	registry["challtestsrv"] = func(_ context.Context, _ providerOpts, env map[string]string) (challenge.Provider, error) {
		u := env["CHALLTESTSRV_URL"]
		if u == "" {
			return nil, fmt.Errorf("challtestsrv: 需要 CHALLTESTSRV_URL")
		}
		return &challtestsrvProvider{mgmtURL: u}, nil
	}
	envNames["challtestsrv"] = []string{"CHALLTESTSRV_URL"}
	t.Cleanup(func() {
		if hadBuild {
			registry["challtestsrv"] = oldBuild
		} else {
			delete(registry, "challtestsrv")
		}
		envNames["challtestsrv"] = oldNames
	})
}

// setupObtainable 预置可真实签发的环境：pebble + challtestsrv 测试 provider
// + account（引用 cts）+ role。pebble 缺失时 Skip（与 startPebble 一致）。
func setupObtainable(t *testing.T) (*backend, logical.Storage, *pebbleEnv) {
	t.Helper()
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CHALLTESTSRV_URL": env.MgmtURL,
	}))
	// 跳过 lego 传播预检：TXT 由测试 provider 即时直写 challtestsrv，
	// pebble VA（-dnsserver 127.0.0.1:8053）可立即读到，无需递归/权威检查。
	b.dns01Opts = []dns01.ChallengeOption{dns01.PropagationWait(time.Millisecond, true)}
	registerChalltestsrvProvider(t)
	// 跳过 Present 内的 CNAME 解析（单测环境无外网 DNS）。
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	ctx := context.Background()

	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key: "dns-providers/cts",
		Value: mustJSON(t, &dnsProviderEntry{
			Type:           "challtestsrv",
			CredentialsRef: &credentialsRef{Mount: "secret", Path: "dns/cts"},
		}),
	}))

	data := accountData(env.DirURL)
	data["dns_providers"] = []interface{}{map[string]interface{}{"name": "cts"}}
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, ClientToken: "test-token", Data: data,
	})
	require.NoError(t, err)
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage, ClientToken: "test-token",
		Data: map[string]interface{}{
			"account":            "le",
			"allowed_domains":    "example.com",
			"allow_bare_domains": true,
			"allow_subdomains":   true,
		},
	})
	require.NoError(t, err)
	return b, storage, env
}

// TestIssueSingleflightWaitersRefcount：并发首发同 key 时 N 个调用方各得
// 一个 lease（singleflight 共享同一响应），等待者必须为其 lease 补引用，
// 维持不变式 Users == 持有该条目的 lease 数。修复前仅领导者计入（Users=1）
// ——本测试即该缺陷的 RED。
func TestIssueSingleflightWaitersRefcount(t *testing.T) {
	b, storage, _ := setupObtainable(t)
	ctx := context.Background()

	const n = 4
	type result struct {
		resp *logical.Response
		err  error
	}
	results := make(chan result, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation, Path: "certs/web",
				Storage: storage, ClientToken: "test-token",
				Data: map[string]interface{}{"common_name": "example.com"},
			})
			results <- result{resp, err}
		}()
	}
	close(start) // N 个请求同时出发，重叠于 singleflight 窗口内

	role, err := b.getRole(ctx, storage, "web")
	require.NoError(t, err)
	key := cacheKey(role, []string{"example.com"})

	for i := 0; i < n; i++ {
		r := <-results
		require.NoError(t, r.err)
		require.NotNil(t, r.resp)
		require.False(t, r.resp.IsError(), "并发签发应成功: %v", r.resp)
		require.NotEmpty(t, r.resp.Data["certificate"])
	}
	entry, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, n, entry.Users, "N 个调用方各持一个 lease，Users 应为 N（等待者补引用缺失）")
}

// TestRenewReissueWaitersRefcount：并发重签同 key 时等待者共享领导者的新
// 证书响应并各自续 lease，须补引用。该分支在 certRenew 中已存在，本测试
// 为回归守护（签发路径等待者分支的 RED 由 TestIssueSingleflightWaitersRefcount
// 承担）。
func TestRenewReissueWaitersRefcount(t *testing.T) {
	b, storage, _ := setupObtainable(t)
	ctx := context.Background()

	// 种入过期条目（Users=2，模拟 2 个 lease 均待续期），key 与真实签发一致。
	role, err := b.getRole(ctx, storage, "web")
	require.NoError(t, err)
	domains := []string{"example.com"}
	key := cacheKey(role, domains)
	base := time.Now()
	require.NoError(t, b.cachePut(ctx, storage, key, &cacheEntry{
		Users: 2, Account: "le", CN: domains[0], Domains: domains,
		CertificatePEM: selfSignedCertFor(t, base.Add(-100*time.Hour), base.Add(-time.Hour)),
	}))

	const n = 2
	type result struct {
		resp *logical.Response
		err  error
	}
	results := make(chan result, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			resp, err := b.certRenew(ctx, leaseReq(storage, key), nil)
			results <- result{resp, err}
		}()
	}
	close(start)
	for i := 0; i < n; i++ {
		r := <-results
		require.NoError(t, r.err)
		require.NotNil(t, r.resp)
		require.False(t, r.resp.IsError(), "重签应成功: %v", r.resp)
	}
	entry, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	// 领导者重签（初始 Users=1）+ 等待者补 1 = 2，对应 2 个续期后的 lease。
	require.Equal(t, n, entry.Users)
}

// TestIssueSkipsPropagationCheckViaDNSProvider：dns-provider 条目的
// skip_propagation_check 经 buildRoutes 聚合为请求级 dns01 选项（Task 14
// 验收链路依赖的生产机制）——不注入 b.dns01Opts 测试缝，仅凭条目即可真实
// 签发。skip=false 的反例（默认预检轮询公网权威 NS 至超时）耗时长且依赖
// 外网 DNS，不在单测覆盖。
func TestIssueSkipsPropagationCheckViaDNSProvider(t *testing.T) {
	b, storage, _ := setupObtainable(t)
	// 拆除测试缝：预检跳过必须来自 dns-provider 条目（生产路径）。
	b.dns01Opts = nil
	ctx := context.Background()

	raw, err := storage.Get(ctx, "dns-providers/cts")
	require.NoError(t, err)
	var entry dnsProviderEntry
	require.NoError(t, raw.DecodeJSON(&entry))
	entry.SkipPropagationCheck = true
	entry.PropagationWait = 1
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key: "dns-providers/cts", Value: mustJSON(t, &entry),
	}))

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage, ClientToken: "test-token",
		Data: map[string]interface{}{"common_name": "example.com"},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "签发应成功: %v", resp)
	require.NotEmpty(t, resp.Data["certificate"])
}
