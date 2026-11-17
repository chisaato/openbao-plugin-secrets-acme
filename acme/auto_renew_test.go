package acme

import (
	"context"
	"testing"
	"time"

	pluginapi "github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// writeFailKVWriter：Read 成功（占用检查通过）但 Write 网络失败——驱动
// writeCertOutput BestEffort 下唯一返回错误的分支。
type writeFailKVWriter struct{ err error }

func (w *writeFailKVWriter) Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error {
	return w.err
}

func (w *writeFailKVWriter) Read(ctx context.Context, clientToken, mount, path string) (map[string]interface{}, error) {
	return nil, nil
}

func (w *writeFailKVWriter) Delete(ctx context.Context, clientToken, mount, path string) error {
	return w.err
}

// countingIssueFn 统计 Obtain 次数并返回固定有效期的 fake 签发结果。
func countingIssueFn(t *testing.T, count *int, notBefore, notAfter time.Time) func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error) {
	t.Helper()
	return func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error) {
		*count++
		return &certificate.Resource{
			Domains:           domains,
			PrivateKey:        []byte("K2"),
			Certificate:       []byte(selfSignedCertFor(t, notBefore, notAfter)),
			IssuerCertificate: []byte("I2"),
			CertURL:           "https://acme.test/cert/2",
		}, nil
	}
}

// autoRenewFixture：account le + 计数 issueFn（24h 有效期新证书）+ 记录型
// kvWriter。role 由各测试自行写入（OutputKVMount/ratio 各异）。
func autoRenewFixture(t *testing.T) (*backend, logical.Storage, context.Context, *int, *recordingKVWriter) {
	t.Helper()
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()
	count := 0
	base := time.Now().UTC().Truncate(time.Second)
	b.issueFn = countingIssueFn(t, &count, base.Add(-time.Hour), base.Add(24*time.Hour))
	kv := &recordingKVWriter{}
	b.kvWriter = kv
	return b, storage, ctx, &count, kv
}

// autoRenewPutEntry 直写一条指定归属与证书的缓存条目并返回其 cacheKey。
func autoRenewPutEntry(t *testing.T, b *backend, ctx context.Context, s logical.Storage, domains []string, account, role, cn string, users int, certPEM string) string {
	t.Helper()
	acc, err := b.getAccount(ctx, s, "le")
	require.NoError(t, err)
	require.NotNil(t, acc)
	key := cacheKey(acc, domains)
	require.NoError(t, b.cachePut(ctx, s, key, &cacheEntry{
		Users: users, Account: account, Role: role, CN: cn, Domains: domains,
		CertificatePEM: certPEM, PrivateKeyPEM: "K", IssuerCertificatePEM: "I",
	}))
	return key
}

// staleCertPEM：总寿命 24h、剩余 12h（50% < 默认 70% 阈值）→ certNeedsRenewal=true。
func staleCertPEM(t *testing.T) string {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Second)
	return selfSignedCertFor(t, base.Add(-12*time.Hour), base.Add(12*time.Hour))
}

// TestAutoRenewScanSkipsFresh：新鲜条目不得触发 Obtain。
func TestAutoRenewScanSkipsFresh(t *testing.T) {
	b, storage, ctx, count, _ := autoRenewFixture(t)
	putRoleFixtureAt(t, ctx, storage, "web", &roleEntry{Account: "le", CacheForRatio: 70, AllowAnyName: true})

	base := time.Now().UTC().Truncate(time.Second)
	fresh := selfSignedCertFor(t, base.Add(-time.Hour), base.Add(24*time.Hour))
	autoRenewPutEntry(t, b, ctx, storage, []string{"example.com"}, "le", "web", "example.com", 1, fresh)

	b.autoRenewScan(ctx, storage)
	require.Equal(t, 0, *count, "新鲜条目不应触发 ACME Obtain")
}

// TestAutoRenewScanRenewsStale：陈旧条目触发重签，Users 保留且 KV 投影刷新。
func TestAutoRenewScanRenewsStale(t *testing.T) {
	b, storage, ctx, count, kv := autoRenewFixture(t)
	putRoleFixtureAt(t, ctx, storage, "web", &roleEntry{
		Account: "le", CacheForRatio: 70, AllowAnyName: true, OutputKVMount: "certs",
	})

	key := autoRenewPutEntry(t, b, ctx, storage, []string{"example.com"}, "le", "web", "example.com", 3, staleCertPEM(t))

	b.autoRenewScan(ctx, storage)
	require.Equal(t, 1, *count, "陈旧条目应恰好触发一次 ACME Obtain")

	entry, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, 3, entry.Users, "后台重签不得重置引用计数")
	require.Equal(t, "K2", entry.PrivateKeyPEM, "证书应已被替换为新签发结果")
	require.Equal(t, pluginapi.KVStatusWritten, entry.OutputKVStatus)
	require.Equal(t, "certs", entry.OutputKVMount)
	require.Len(t, kv.writes, 1, "KV 投影应刷新一次")
}

// TestAutoRenewScanSkipsMissingRole：签发 role 已删除的条目跳过且不清理。
func TestAutoRenewScanSkipsMissingRole(t *testing.T) {
	b, storage, ctx, count, _ := autoRenewFixture(t)
	putRoleFixtureAt(t, ctx, storage, "web", &roleEntry{Account: "le", CacheForRatio: 70, AllowAnyName: true})

	autoRenewPutEntry(t, b, ctx, storage, []string{"example.com"}, "le", "ghost", "example.com", 1, staleCertPEM(t))

	b.autoRenewScan(ctx, storage)
	require.Equal(t, 0, *count)
}

// TestAutoRenewScanSkipsMissingAccount：签发 account 已删除的条目跳过。
func TestAutoRenewScanSkipsMissingAccount(t *testing.T) {
	b, storage, ctx, count, _ := autoRenewFixture(t)
	putRoleFixtureAt(t, ctx, storage, "web", &roleEntry{Account: "le", CacheForRatio: 70, AllowAnyName: true})

	autoRenewPutEntry(t, b, ctx, storage, []string{"example.com"}, "ghost", "web", "example.com", 1, staleCertPEM(t))

	b.autoRenewScan(ctx, storage)
	require.Equal(t, 0, *count)
}

// TestAutoRenewScanSkipsLegacyEntry：无 role 字段的旧条目（Role==""）保守跳过。
func TestAutoRenewScanSkipsLegacyEntry(t *testing.T) {
	b, storage, ctx, count, _ := autoRenewFixture(t)
	putRoleFixtureAt(t, ctx, storage, "web", &roleEntry{Account: "le", CacheForRatio: 70, AllowAnyName: true})

	autoRenewPutEntry(t, b, ctx, storage, []string{"example.com"}, "le", "", "example.com", 1, staleCertPEM(t))

	b.autoRenewScan(ctx, storage)
	require.Equal(t, 0, *count)
}

// TestAutoRenewOneRecheckFresh：singleflight 闭包内复查命中（条目已被并发
// 调用者刷新）时不再 Obtain，直接以现有条目组装响应。
func TestAutoRenewOneRecheckFresh(t *testing.T) {
	b, storage, ctx, count, _ := autoRenewFixture(t)
	role := &roleEntry{Account: "le", CacheForRatio: 70, AllowAnyName: true}
	putRoleFixtureAt(t, ctx, storage, "web", role)

	base := time.Now().UTC().Truncate(time.Second)
	fresh := selfSignedCertFor(t, base.Add(-time.Hour), base.Add(24*time.Hour))
	key := autoRenewPutEntry(t, b, ctx, storage, []string{"example.com"}, "le", "web", "example.com", 2, fresh)

	acc, err := b.getAccount(ctx, storage, "le")
	require.NoError(t, err)
	entry, gerr := b.cacheGet(ctx, storage, key)
	require.NoError(t, gerr)
	// 绕过 scan 的新鲜度闸门直调 autoRenewOne：闭包复查应兜底跳过。
	b.autoRenewOne(ctx, storage, key, role, acc, entry)
	require.Equal(t, 0, *count, "复查命中后不应再次 Obtain")
}

// TestRenewEntryResponseContract：renewEntry 返回的响应须满足 singleflight
// 调用点契约——非空 *logical.Response、含 Secret（Renewable + MaxTTL=剩余寿命）
// 与 not_before/not_after。
func TestRenewEntryResponseContract(t *testing.T) {
	b, storage, ctx, _, _ := autoRenewFixture(t)
	role := &roleEntry{Account: "le", CacheForRatio: 70, AllowAnyName: true}
	putRoleFixtureAt(t, ctx, storage, "web", role)

	key := autoRenewPutEntry(t, b, ctx, storage, []string{"example.com"}, "le", "web", "example.com", 1, staleCertPEM(t))

	acc, err := b.getAccount(ctx, storage, "le")
	require.NoError(t, err)
	resp, rerr := b.renewEntry(ctx, storage, key, "web", role, acc)
	require.NoError(t, rerr)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Secret, "并发 sync 等待者依赖 Secret 建 lease")
	require.True(t, resp.Secret.Renewable)
	require.Greater(t, int64(resp.Secret.LeaseOptions.MaxTTL), int64(0))
	require.NotEmpty(t, resp.Data["not_after"])
	require.Equal(t, "K2", resp.Data["private_key"])
}

// TestRenewEntryKVWriteFailureKeepsEntry：KV Write 网络失败不删除缓存条目
// （与同步路径 KV 硬失败删条目语义相反），仅置 skipped_error 保留 Users。
func TestRenewEntryKVWriteFailureKeepsEntry(t *testing.T) {
	b, storage, ctx, _, _ := autoRenewFixture(t)
	putRoleFixtureAt(t, ctx, storage, "web", &roleEntry{
		Account: "le", CacheForRatio: 70, AllowAnyName: true, OutputKVMount: "certs",
	})
	b.kvWriter = &writeFailKVWriter{err: context.DeadlineExceeded}

	key := autoRenewPutEntry(t, b, ctx, storage, []string{"example.com"}, "le", "web", "example.com", 3, staleCertPEM(t))

	acc, err := b.getAccount(ctx, storage, "le")
	require.NoError(t, err)
	role, gerr := b.getRole(ctx, storage, "web")
	require.NoError(t, gerr)
	_, rerr := b.renewEntry(ctx, storage, key, "web", role, acc)
	require.NoError(t, rerr, "KV Write 失败不得让后台续签整体失败")

	entry, cerr := b.cacheGet(ctx, storage, key)
	require.NoError(t, cerr)
	require.NotNil(t, entry, "KV 失败不得删除缓存条目")
	require.Equal(t, 3, entry.Users)
	require.Equal(t, "K2", entry.PrivateKeyPEM, "证书本体应已续签成功")
	require.Equal(t, pluginapi.KVStatusSkippedError, entry.OutputKVStatus)
}

// TestAutoRenewEnv：逃生口与间隔解析。
func TestAutoRenewEnv(t *testing.T) {
	t.Setenv("BAO_ACME_AUTORENEW_DISABLE", "1")
	require.True(t, autoRenewDisabled())
	t.Setenv("BAO_ACME_AUTORENEW_DISABLE", "true")
	require.True(t, autoRenewDisabled())
	t.Setenv("BAO_ACME_AUTORENEW_DISABLE", "false")
	require.False(t, autoRenewDisabled())
	t.Setenv("BAO_ACME_AUTORENEW_DISABLE", "0")
	require.False(t, autoRenewDisabled())
	t.Setenv("BAO_ACME_AUTORENEW_DISABLE", "")
	require.False(t, autoRenewDisabled())

	t.Setenv("BAO_ACME_AUTORENEW_INTERVAL", "30m")
	require.Equal(t, 30*time.Minute, autoRenewInterval())
	t.Setenv("BAO_ACME_AUTORENEW_INTERVAL", "90s")
	require.Equal(t, 90*time.Second, autoRenewInterval())
	t.Setenv("BAO_ACME_AUTORENEW_INTERVAL", "bogus")
	require.Equal(t, time.Hour, autoRenewInterval(), "解析失败回退默认")
	t.Setenv("BAO_ACME_AUTORENEW_INTERVAL", "0s")
	require.Equal(t, time.Hour, autoRenewInterval(), "非正值回退默认")
	t.Setenv("BAO_ACME_AUTORENEW_INTERVAL", "")
	require.Equal(t, time.Hour, autoRenewInterval(), "未设置回退默认")
}
