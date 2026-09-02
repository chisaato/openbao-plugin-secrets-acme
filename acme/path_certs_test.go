package acme

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// setupIssuable 预置：pebble、dns-provider/exec 记录（直写存储绕过 fail-fast
// 试读）、account（未引用任何 dns provider，供路由缺失断言）、role。
// 说明：v1 仅 DNS-01，单测环境无法真正落 TXT（fake provider 不产生记录），
// 真实端到端签发由 Task 14 验收测试（exec provider + challtestsrv）覆盖；
// 本文件聚焦校验逻辑与「失败路径不落缓存/不写 KV」。
func setupIssuable(t *testing.T) (*backend, logical.Storage, *pebbleEnv, string) {
	t.Helper()
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 注册 dns-provider 记录（本组用例不经过 buildRoutes，仅补全环境）
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key: "dns-providers/exec",
		Value: mustJSON(t, &dnsProviderEntry{
			Type:           "cloudflare",
			CredentialsRef: &credentialsRef{Mount: "secret", Path: "dns/cf"},
		}),
	}))

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	})
	require.NoError(t, err)
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":            "le",
			"allowed_domains":    "example.com",
			"allow_bare_domains": true,
			"allow_subdomains":   true,
		},
	})
	require.NoError(t, err)
	return b, storage, env, "exec"
}

func TestIssuePathValidation(t *testing.T) {
	b, storage, _, _ := setupIssuable(t)
	ctx := context.Background()

	// 域名不在白名单 → 报错
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage,
		Data:    map[string]interface{}{"common_name": "evil.com"},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "不在 allowed_domains 内")

	// 白名单内但 provider 路由缺失（account 无 dns_providers）→ 报错含"路由"
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage,
		Data:    map[string]interface{}{"common_name": "example.com"},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "路由")
}

func TestIssueWithFakeProvider(t *testing.T) {
	// 路由与凭据/provider 构造成功，但 TXT 无法真正落地（fake token 无法写
	// Cloudflare，pebble 侧校验失败）——聚焦「失败前」的路径：响应错误但
	// 缓存未生成、无 KV 写入。
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))
	ctx := context.Background()

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "dns-providers/cf",
		Storage: storage, ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":            "cloudflare",
			"credentials_ref": map[string]interface{}{"mount": "s", "path": "p"},
		},
	})
	require.NoError(t, err)

	data := accountData(env.DirURL)
	data["dns_providers"] = []interface{}{map[string]interface{}{"name": "cf"}}
	_, err = b.HandleRequest(ctx, &logical.Request{
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
			"output_kv_mount":    "kv-certs",
		},
	})
	require.NoError(t, err)

	w := &recordingKVWriter{}
	b.kvWriter = w

	// 签发：路由与凭据/provider 构造成功，TXT 无法真正落地（pebble 侧校验失败）
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage, ClientToken: "test-token",
		Data: map[string]interface{}{"common_name": "example.com"},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError()) // pebble DNS 校验失败（预期）
	require.Empty(t, w.writes)      // 失败不写 KV
	n, _ := b.cacheCount(ctx, storage)
	require.Equal(t, 0, n) // 失败不落缓存
}

// ---- 缓存命中类测试的夹具：直写 account/role（无需 pebble/ACME 交互）----

func putRoleFixture(t *testing.T, ctx context.Context, storage logical.Storage, role *roleEntry) {
	t.Helper()
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key: "accounts/le",
		Value: mustJSON(t, &accountEntry{
			Name: "le", ServerURL: "https://acme.test/dir", Contact: "admin@example.com",
		}),
	}))
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key:   "roles/web",
		Value: mustJSON(t, role),
	}))
}

// putFreshCacheEntry 预置一条新鲜（剩余寿命约 96% > 默认 70%）的缓存条目。
func putFreshCacheEntry(t *testing.T, b *backend, ctx context.Context, storage logical.Storage, role *roleEntry, domains []string) string {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Second)
	entry := &cacheEntry{
		Users: 1, Account: role.Account, CN: domains[0], Domains: domains,
		CertificatePEM: selfSignedCertFor(t, base.Add(-time.Hour), base.Add(24*time.Hour)),
		PrivateKeyPEM:  "K", IssuerCertificatePEM: "I",
	}
	key := cacheKey(role, domains)
	require.NoError(t, b.cachePut(ctx, storage, key, entry))
	return key
}

func issueRequest(ctx context.Context, storage logical.Storage) *logical.Request {
	return &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage, ClientToken: "test-token",
		Data: map[string]interface{}{"common_name": "example.com"},
	}
}

// TestIssueCacheHitResponse 验证缓存命中成功路径的响应契约：
// not_before/not_after 必须存在且为可解析的 RFC3339 字符串（与 KV 输出语义一致）。
func TestIssueCacheHitResponse(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, role)
	key := putFreshCacheEntry(t, b, ctx, storage, role, []string{"example.com"})

	resp, err := b.HandleRequest(ctx, issueRequest(ctx, storage))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "缓存命中应成功: %v", resp)

	// not_before/not_after：存在、RFC3339 可解析、等于夹具证书有效期
	nb, ok := resp.Data["not_before"].(string)
	require.True(t, ok, "not_before 须为字符串，got %T", resp.Data["not_before"])
	na, ok := resp.Data["not_after"].(string)
	require.True(t, ok, "not_after 须为字符串，got %T", resp.Data["not_after"])
	parsedNB, err := time.Parse(time.RFC3339, nb)
	require.NoError(t, err)
	parsedNA, err := time.Parse(time.RFC3339, na)
	require.NoError(t, err)
	fixture, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.NotNil(t, fixture)
	_, wantAfter := certValidity(fixture.CertificatePEM)
	require.True(t, parsedNA.Equal(wantAfter), "not_after=%s 应等于证书 NotAfter", na)
	require.True(t, parsedNB.Before(parsedNA))

	// 其余响应契约与引用计数
	require.Equal(t, "example.com", resp.Data["common_name"])
	require.Equal(t, fixture.CertificatePEM, resp.Data["certificate"])
	require.Greater(t, resp.Secret.LeaseOptions.MaxTTL, time.Duration(0))
	require.Equal(t, "le", resp.Secret.InternalData["account"])
	require.Equal(t, key, resp.Secret.InternalData["cache_key"])
	require.Equal(t, 2, fixture.Users, "命中一次后 Users 应为 2")
}

// TestIssueCacheHitConcurrentUsers 并发命中同 key N 次后 Users 必须精确为
// 初始 1+N：暴露 cacheGet(RLock)→内存自增→cachePut(Lock) 三段式临界区的
// 丢失更新（修复后走单临界区 cacheUpdate）。
func TestIssueCacheHitConcurrentUsers(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, role)
	key := putFreshCacheEntry(t, b, ctx, storage, role, []string{"example.com"})

	const n = 50
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := b.HandleRequest(ctx, issueRequest(ctx, storage))
			if err != nil {
				errCh <- err
				return
			}
			if resp.IsError() {
				errCh <- fmt.Errorf("命中失败: %v", resp.Data["error"])
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	entry, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, 1+n, entry.Users, "并发 N 次命中不得丢失 Users 更新")
}

// failingKVWriter 强制失败的 KV writer（I-3：KV 输出失败不得留下孤儿引用计数）。
type failingKVWriter struct{ err error }

func (w *failingKVWriter) Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error {
	return w.err
}

func TestIssueKVFailureDropsCacheEntry(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	putRoleFixture(t, ctx, storage, role)
	key := putFreshCacheEntry(t, b, ctx, storage, role, []string{"example.com"})

	b.kvWriter = &failingKVWriter{err: errors.New("kv unavailable")}

	// 缓存命中路径：KV 输出失败 → 报错，且整条缓存条目被删除
	// （错误响应无 Secret、core 不建 lease，残留条目即无人释放的孤儿引用）。
	resp, err := b.HandleRequest(ctx, issueRequest(ctx, storage))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "KV 输出失败")

	gone, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.Nil(t, gone, "KV 输出失败后缓存条目应被删除")
}
