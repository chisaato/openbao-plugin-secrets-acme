package acme

import (
	"context"
	"testing"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// kvOpsRequest 构造手动 KV 投影端点的请求。
func kvOpsRequest(op logical.Operation, path string, s logical.Storage, data map[string]interface{}) *logical.Request {
	return &logical.Request{Operation: op, Path: path, Storage: s, ClientToken: "test-token", Data: data}
}

// seedKVOpEntry：直写角色/账户与缓存条目，返回 cacheKey。
func seedKVOpEntry(t *testing.T, b *backend, ctx context.Context, s logical.Storage, role *roleEntry, cn string, entry *cacheEntry) string {
	t.Helper()
	putAccountRaw(t, ctx, s, "le")
	putRoleRaw(t, ctx, s, "web", role)
	if entry.Role == "" {
		entry.Role = "web"
	}
	if entry.CN == "" {
		entry.CN = cn
	}
	key := cacheKey(role, entry.Domains)
	require.NoError(t, b.cachePut(ctx, s, key, entry))
	return key
}

// TestCertKVSyncUnconfigured：role 未配 output_kv_mount 且证书未 link → 错误响应。
func TestCertKVSyncUnconfigured(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: "C", PrivateKeyPEM: "K",
	})
	b.kvWriter = &recordingKVWriter{}

	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/sync", s, nil))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "未配置 KV 输出")

	// 条目不存在 → 404（nil, nil）。
	resp, err = b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/missing.example.com/kv/sync", s, nil))
	require.NoError(t, err)
	require.Nil(t, resp)
}

// TestCertKVSyncSuccess：role 配置 mount 后 sync 成功重投影且条目字段更新。
func TestCertKVSyncSuccess(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	key := seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: "C", PrivateKeyPEM: "K",
	})
	w := &recordingKVWriter{}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/sync", s, nil))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "sync: %v", resp)
	require.Equal(t, api.KVStatusWritten, resp.Data["output_kv_status"])
	require.Equal(t, "kv-certs", resp.Data["output_kv_mount"])
	require.Equal(t, "kv-certs/certs/"+key, resp.Data["output_kv_path"])
	require.Len(t, w.writes, 1)
	require.Equal(t, "kv-certs", w.writes[0].mount)
	require.Equal(t, "certs/"+key, w.writes[0].path)

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.Equal(t, api.KVStatusWritten, entry.OutputKVStatus)
	require.Equal(t, "kv-certs", entry.OutputKVMount)
	require.Equal(t, "kv-certs/certs/"+key, entry.OutputKVPath)
}

// TestCertKVSyncConflict：冲突时 Enforce 报错，force=true 覆盖成功。
func TestCertKVSyncConflict(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	key := seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: "C", PrivateKeyPEM: "K",
	})
	w := &recordingKVWriter{preset: conflictPreset("kv-certs", key)}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/sync", s, nil))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "占用")
	require.Contains(t, resp.Error().Error(), "force")
	require.Empty(t, w.writes)
	readsBefore := len(w.reads)

	resp, err = b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/sync", s,
		map[string]interface{}{"force": true}))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "force sync: %v", resp)
	require.Len(t, w.writes, 1)
	require.Equal(t, readsBefore, len(w.reads), "Overwrite 策略应跳过占用检查")
}

// TestCertKVLink：设置 mount+自定义 path 后条目字段与 KV 数据位置正确。
func TestCertKVLink(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	key := seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: "C", PrivateKeyPEM: "K",
	})
	w := &recordingKVWriter{}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/link", s,
		map[string]interface{}{"mount": "kv-link", "path": "my/cert"}))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "link: %v", resp)
	require.Equal(t, api.KVStatusWritten, resp.Data["output_kv_status"])
	require.Equal(t, "kv-link", resp.Data["output_kv_mount"])
	require.Equal(t, "kv-link/my/cert", resp.Data["output_kv_path"])
	require.Len(t, w.writes, 1)
	require.Equal(t, "kv-link", w.writes[0].mount)
	require.Equal(t, "my/cert", w.writes[0].path)

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.True(t, entry.OutputKVLinked)
	require.Equal(t, "kv-link", entry.OutputKVMount)
	require.Equal(t, "my/cert", entry.OutputKVPathOverride)
	require.Equal(t, "kv-link/my/cert", entry.OutputKVPath)
	require.Equal(t, api.KVStatusWritten, entry.OutputKVStatus)
}

// TestCertKVLinkValidation：缺 mount 且 role 未配置、path 非法 → 报错。
func TestCertKVLinkValidation(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: "C", PrivateKeyPEM: "K",
	})
	b.kvWriter = &recordingKVWriter{}

	// 缺 mount 且 role 未配置。
	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/link", s, nil))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "未配置 KV 输出")

	// 非法 path：含 ".." 段 / 以 "/" 开头 / 以 "/" 结尾。
	for _, bad := range []string{"a/../b", "/abs", "trailing/"} {
		resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/link", s,
			map[string]interface{}{"mount": "kv-link", "path": bad}))
		require.NoError(t, err)
		require.True(t, resp.IsError(), "path %q 应被拒绝", bad)
	}
}

// TestCertKVLinkRollback：link 写入冲突且未 force 时回滚三个绑定字段。
func TestCertKVLinkRollback(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	key := seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: "C", PrivateKeyPEM: "K",
		OutputKVMount: "old-mount", OutputKVPathOverride: "old", OutputKVPath: "old-mount/old",
		OutputKVStatus: api.KVStatusWritten,
	})
	w := &recordingKVWriter{preset: map[string]map[string]interface{}{
		"kv-link/new": {"cert_id": "other"},
	}}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/link", s,
		map[string]interface{}{"mount": "kv-link", "path": "new"}))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "force")
	require.Empty(t, w.writes)

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.False(t, entry.OutputKVLinked, "失败的 link 不应置位")
	require.Equal(t, "old-mount", entry.OutputKVMount)
	require.Equal(t, "old", entry.OutputKVPathOverride)
	require.Equal(t, "old-mount/old", entry.OutputKVPath)
	require.Equal(t, api.KVStatusWritten, entry.OutputKVStatus)
}

// TestCertKVUnlinkKeepData：默认不删 KV 数据，条目投影字段清空。
func TestCertKVUnlinkKeepData(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	key := seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: "C", PrivateKeyPEM: "K",
		OutputKVLinked: true, OutputKVMount: "kv-link", OutputKVPathOverride: "my/cert",
		OutputKVPath: "kv-link/my/cert", OutputKVStatus: api.KVStatusWritten,
	})
	w := &recordingKVWriter{}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/unlink", s, nil))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "unlink: %v", resp)
	require.Equal(t, true, resp.Data["unlinked"])
	require.Equal(t, false, resp.Data["kv_deleted"])
	require.Empty(t, w.deletes, "默认不应删除 KV 数据")

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.False(t, entry.OutputKVLinked)
	require.Empty(t, entry.OutputKVMount)
	require.Empty(t, entry.OutputKVPathOverride)
	require.Empty(t, entry.OutputKVPath)
	require.Empty(t, entry.OutputKVStatus)
}

// TestCertKVUnlinkDeleteData：delete_kv=true 时按绑定位置（mount+override）删除。
func TestCertKVUnlinkDeleteData(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: "C", PrivateKeyPEM: "K",
		OutputKVLinked: true, OutputKVMount: "kv-link", OutputKVPathOverride: "my/cert",
		OutputKVPath: "kv-link/my/cert", OutputKVStatus: api.KVStatusWritten,
	})
	w := &recordingKVWriter{}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/unlink", s,
		map[string]interface{}{"delete_kv": true}))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "unlink: %v", resp)
	require.Equal(t, true, resp.Data["unlinked"])
	require.Equal(t, true, resp.Data["kv_deleted"])
	require.Len(t, w.deletes, 1)
	require.Equal(t, "kv-link", w.deletes[0].mount)
	require.Equal(t, "my/cert", w.deletes[0].path)
}

// TestCertKVRenewFollowsLink：link 后 renew 写入 link 的 mount/path；unlink 且
// role 无 mount 后 renew 不写。
func TestCertKVRenewFollowsLink(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	base := time.Now()
	key := seedKVOpEntry(t, b, ctx, s, role, "example.com", &cacheEntry{
		Users: 1, Account: "le", Domains: []string{"example.com"},
		CertificatePEM: selfSignedCertFor(t, base.Add(-100*time.Hour), base.Add(-time.Hour)),
		PrivateKeyPEM:  "K",
	})
	b.issueFn = stubIssueFn(t)
	w := &recordingKVWriter{}
	b.kvWriter = w

	// link 建立绑定。
	resp, err := b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/link", s,
		map[string]interface{}{"mount": "kv-link", "path": "my/cert"}))
	require.NoError(t, err)
	require.False(t, resp.IsError(), "link: %v", resp)
	require.Len(t, w.writes, 1)

	// renew 沿 link 的 mount/path 写入。
	renewResp, err := b.certRenew(ctx, leaseReq(s, key), nil)
	require.NoError(t, err)
	require.NotNil(t, renewResp)
	require.False(t, renewResp.IsError())
	require.Len(t, w.writes, 2, "续签应沿 link 写入一次")
	require.Equal(t, "kv-link", w.writes[1].mount)
	require.Equal(t, "my/cert", w.writes[1].path)

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.True(t, entry.OutputKVLinked, "续签后 link 标记应保持")
	require.Equal(t, "kv-link", entry.OutputKVMount)
	require.Equal(t, "my/cert", entry.OutputKVPathOverride)

	// unlink（role 无 mount）后 renew 不再写 KV。
	resp, err = b.HandleRequest(ctx, kvOpsRequest(logical.UpdateOperation, "certs/web/example.com/kv/unlink", s, nil))
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// 令证书再次过期，确保 renew 走完整重签路径（而非新鲜短路）。
	entry, err = b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	entry.CertificatePEM = selfSignedCertFor(t, base.Add(-100*time.Hour), base.Add(-time.Hour))
	require.NoError(t, b.cachePut(ctx, s, key, entry))

	writesAfterUnlink := len(w.writes)
	renewResp, err = b.certRenew(ctx, leaseReq(s, key), nil)
	require.NoError(t, err)
	require.NotNil(t, renewResp)
	require.False(t, renewResp.IsError())
	require.Len(t, w.writes, writesAfterUnlink, "unlink 且 role 无 mount 后续签不应写 KV")
}
