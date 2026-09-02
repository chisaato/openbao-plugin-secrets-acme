package acme

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// leaseReq 构造模拟 core 续期/撤销回调的请求。framework 会把签发响应的
// Secret（含 InternalData）复制进 lease 并在回调时回填 req.Secret，单测
// 直接手工构造等价形态。
func leaseReq(storage logical.Storage, key string) *logical.Request {
	return &logical.Request{
		Storage: storage,
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
