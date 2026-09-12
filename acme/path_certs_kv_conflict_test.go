package acme

import (
	"context"
	"testing"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// conflictPreset 构造占用了 certs/{key} 的外来数据。
func conflictPreset(mount, key string) map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		mount + "/certs/" + key: {
			"cert_id":     "other",
			"common_name": "other.com",
			"role":        "other-role",
			"account":     "other-acc",
		},
	}
}

func syncIssueRequest(storage logical.Storage, extra map[string]interface{}) *logical.Request {
	data := map[string]interface{}{"common_name": "example.com", "sync": true}
	for k, v := range extra {
		data[k] = v
	}
	return &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage, ClientToken: "test-token", Data: data,
	}
}

// TestIssueKVConflictRejected：sync 签发遇 KV 路径被其他证书占用 → 拒绝签发，
// 错误含占用详情与 force 提示；并按不变式回滚缓存条目（不留孤儿引用）。
func TestIssueKVConflictRejected(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	putRoleFixture(t, ctx, s, role)
	key := cacheKey(role, []string{"example.com"})
	b.issueFn = stubIssueFn(t)

	w := &recordingKVWriter{preset: conflictPreset("kv-certs", key)}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, syncIssueRequest(s, nil))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	msg := resp.Error().Error()
	require.Contains(t, msg, "占用")
	require.Contains(t, msg, "other")
	require.Contains(t, msg, "force")
	require.Empty(t, w.writes)

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.Nil(t, entry, "冲突拒绝后缓存条目应被回滚")
}

// TestIssueKVConflictForceOverwrite：force=true → 跳过占用检查直接覆写。
func TestIssueKVConflictForceOverwrite(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	putRoleFixture(t, ctx, s, role)
	key := cacheKey(role, []string{"example.com"})
	b.issueFn = stubIssueFn(t)

	w := &recordingKVWriter{preset: conflictPreset("kv-certs", key)}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, syncIssueRequest(s, map[string]interface{}{"force": true}))
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "force 覆盖应成功: %v", resp)
	require.Len(t, w.writes, 1)
	require.Empty(t, w.reads, "Overwrite 策略应跳过占用检查")

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, api.KVStatusWritten, entry.OutputKVStatus)
	require.Equal(t, "kv-certs", entry.OutputKVMount)
	require.Equal(t, "kv-certs/certs/"+key, entry.OutputKVPath)
}

// TestIssueKVSelfVersionAllowed：目标路径现存数据 cert_id 与本次一致（自己的
// 旧版本/续期重签）→ 允许覆写。
func TestIssueKVSelfVersionAllowed(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	putRoleFixture(t, ctx, s, role)
	key := cacheKey(role, []string{"example.com"})
	b.issueFn = stubIssueFn(t)

	w := &recordingKVWriter{preset: map[string]map[string]interface{}{
		"kv-certs/certs/" + key: {"cert_id": key, "common_name": "example.com"},
	}}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, syncIssueRequest(s, nil))
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "自身旧版本应允许覆写: %v", resp)
	require.Len(t, w.writes, 1)
	require.Len(t, w.reads, 1)
}

// TestRenewKVConflictBestEffort：lease 自动续期遇冲突 → 跳过 KV 写、续期照常
// 成功，响应无 output_path；投影状态落 skipped_conflict，Mount 保持上次成功值。
func TestRenewKVConflictBestEffort(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putAccountRaw(t, ctx, s, "le")
	putRoleRaw(t, ctx, s, "web", &roleEntry{
		Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs",
	})
	b.issueFn = stubIssueFn(t)

	role, err := storage.GetRole(ctx, s, "web")
	require.NoError(t, err)
	key := cacheKey(role, []string{"example.com"})
	base := time.Now()
	// 预置条目：上次成功写入位置为 old-mount。
	require.NoError(t, s.Put(ctx, &logical.StorageEntry{
		Key: storageKeyCache + key,
		Value: mustJSON(t, &cacheEntry{
			Users: 1, Account: "le", Role: "web", CN: "example.com", Domains: []string{"example.com"},
			CertificatePEM: selfSignedCertFor(t, base.Add(-100*time.Hour), base.Add(-time.Hour)),
			OutputKVMount:  "old-mount", OutputKVStatus: api.KVStatusWritten,
		}),
	}))

	w := &recordingKVWriter{preset: conflictPreset("kv-certs", key)}
	b.kvWriter = w

	resp, err := b.certRenew(ctx, leaseReq(s, key), nil)
	require.NoError(t, err, "续期不应因 KV 冲突被阻断")
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
	_, hasPath := resp.Data["output_path"]
	require.False(t, hasPath, "冲突跳过 KV 写，响应不应有 output_path")
	require.Empty(t, w.writes)

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.NotNil(t, entry, "续期后缓存条目仍在")
	require.Equal(t, api.KVStatusSkippedConflict, entry.OutputKVStatus)
	require.Equal(t, "old-mount", entry.OutputKVMount, "冲突跳过时 Mount 保持上次成功值")
	require.Empty(t, entry.OutputKVPath, "冲突跳过时 Path 未被本次成功写入覆盖（保持旧值）")

	// GET 详情可见
	getResp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "certs/id/" + key, Storage: s})
	require.NoError(t, err)
	require.Equal(t, api.KVStatusSkippedConflict, getResp.Data["output_kv_status"])
	require.Equal(t, "old-mount", getResp.Data["output_kv_mount"])
	require.Equal(t, "old-mount/certs/"+key, getResp.Data["output_kv_path"])
}

// TestRunJobKVConflict：异步 job 遇冲突 → jobFailed，Error 含冲突提示，
// 且按不变式回滚缓存条目。
func TestRunJobKVConflict(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	putRoleFixture(t, ctx, s, role)
	b.issueFn = stubIssueFn(t)
	key := cacheKey(role, []string{"example.com"})

	w := &recordingKVWriter{preset: conflictPreset("kv-certs", key)}
	b.kvWriter = w

	job := &jobEntry{ID: "jobkv", Role: "web", Account: "le", CN: "example.com",
		Domains: []string{"example.com"}, Status: jobPending, CreatedAt: time.Now().UTC()}
	require.NoError(t, b.jobUpdate(ctx, s, job))
	b.runJob(ctx, s, job)

	done := waitForJob(t, b, s, "jobkv")
	require.Equal(t, jobFailed, done.Status)
	require.Contains(t, done.Error, "冲突")
	require.Empty(t, w.writes)

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.Nil(t, entry, "job 冲突失败后应回滚缓存条目")
}

// TestKVProjectionWrittenAndGet：fresh issue 成功后条目记录 written+mount，
// GET 详情与 LIST 摘要均可见。
func TestKVProjectionWrittenAndGet(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	putRoleFixture(t, ctx, s, role)
	key := cacheKey(role, []string{"example.com"})
	b.issueFn = stubIssueFn(t)
	b.kvWriter = &recordingKVWriter{}

	resp, err := b.HandleRequest(ctx, syncIssueRequest(s, nil))
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "issue: %v", resp)
	require.Equal(t, api.KVStatusWritten, resp.Data["output_kv_status"])

	entry, err := b.cacheGet(ctx, s, key)
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, "kv-certs", entry.OutputKVMount)
	require.Equal(t, api.KVStatusWritten, entry.OutputKVStatus)
	require.Equal(t, "kv-certs/certs/"+key, entry.OutputKVPath)

	getResp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "certs/id/" + key, Storage: s})
	require.NoError(t, err)
	require.Equal(t, api.KVStatusWritten, getResp.Data["output_kv_status"])
	require.Equal(t, "kv-certs", getResp.Data["output_kv_mount"])
	require.Equal(t, "kv-certs/certs/"+key, getResp.Data["output_kv_path"])

	listResp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ListOperation, Path: "certs/", Storage: s})
	require.NoError(t, err)
	certs, ok := listResp.Data["certificates"].([]certSummary)
	require.True(t, ok)
	require.Len(t, certs, 1)
	require.Equal(t, api.KVStatusWritten, certs[0].OutputKVStatus)
	require.Equal(t, "kv-certs/certs/"+key, certs[0].OutputKVPath)
}

// TestKVProjectionPathFallbackOldEntry：旧格式条目只记录 OutputKVMount、无
// OutputKVPath 时，GET/LIST 展示层按 mount + certs/{certID} 现场回退拼接。
func TestKVProjectionPathFallbackOldEntry(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "kv-certs"}
	putRoleFixture(t, ctx, s, role)
	key := cacheKey(role, []string{"example.com"})
	base := time.Now()
	// 模拟上一版本写入的条目：有 Mount/Status，无 Path。
	require.NoError(t, s.Put(ctx, &logical.StorageEntry{
		Key: storageKeyCache + key,
		Value: mustJSON(t, &cacheEntry{
			Users: 1, Account: "le", Role: "web", CN: "example.com", Domains: []string{"example.com"},
			CertificatePEM: selfSignedCertFor(t, base.Add(-time.Hour), base.Add(24*time.Hour)),
			OutputKVMount:  "old-mount", OutputKVStatus: api.KVStatusWritten,
		}),
	}))

	getResp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "certs/id/" + key, Storage: s})
	require.NoError(t, err)
	require.Equal(t, "old-mount/certs/"+key, getResp.Data["output_kv_path"], "旧条目应回退拼接完整路径")
	require.Equal(t, "old-mount", getResp.Data["output_kv_mount"])

	listResp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ListOperation, Path: "certs/", Storage: s})
	require.NoError(t, err)
	certs, ok := listResp.Data["certificates"].([]certSummary)
	require.True(t, ok)
	require.Len(t, certs, 1)
	require.Equal(t, "old-mount/certs/"+key, certs[0].OutputKVPath, "LIST 旧条目应回退拼接完整路径")
}

// TestRevokeUsesRecordedMount：撤销清理的 mount 优先条目记录的最后成功写入
// 位置，而非 role 现值。
func TestRevokeUsesRecordedMount(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// role 现值 mount=new-mount；account le 无有效私钥 → CA 真撤销被跳过（无网络）。
	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, OutputKVMount: "new-mount"}
	putRoleFixture(t, ctx, s, role)
	key := cacheKey(role, []string{"example.com"})
	base := time.Now()
	require.NoError(t, s.Put(ctx, &logical.StorageEntry{
		Key: storageKeyCache + key,
		Value: mustJSON(t, &cacheEntry{
			Users: 0, Account: "le", Role: "web", CN: "example.com", Domains: []string{"example.com"},
			CertificatePEM: selfSignedCertFor(t, base.Add(-time.Hour), base.Add(24*time.Hour)),
			OutputKVMount:  "old-mount", OutputKVStatus: api.KVStatusWritten,
		}),
	}))

	w := &recordingKVWriter{}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "certs/id/" + key, Storage: s, ClientToken: "test-token",
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "revoke: %v", resp)
	require.Len(t, w.deletes, 1)
	require.Equal(t, "old-mount", w.deletes[0].mount, "撤销应清理条目记录的最后成功写入位置")
}
