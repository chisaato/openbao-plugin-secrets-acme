package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certificate"
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

func seedJob(t *testing.T, b *backend, ctx context.Context, storage logical.Storage, id string, status jobStatus) *jobEntry {
	t.Helper()
	job := &jobEntry{ID: id, Role: "web", Account: "le", CN: "example.com",
		Domains: []string{"example.com"}, Status: status, CreatedAt: time.Now().UTC()}
	if status == jobCompleted {
		job.Cert = &jobCertSnapshot{CertificatePEM: "CERT", PrivateKeyPEM: "KEY",
			CertURL: "https://acme.test/cert/1", NotAfter: "2026-09-06T00:00:00Z"}
	}
	require.NoError(t, b.jobUpdate(ctx, storage, job))
	return job
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

	// 不变式（spec §7）：异步完成无 lease 持引用 → Users=0
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

	// 同 (role, domains) 挂靠
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

// TestResumeJobsOnInitialize：pending/processing job 在 Initialize 时被重新
// 驱动至终态；completed/failed 不受影响（spec §8）。
func TestResumeJobsOnInitialize(t *testing.T) {
	b, storage, ctx := jobFixture(t)

	for _, tc := range []struct {
		id string
		st jobStatus
	}{
		{"r-pending", jobPending}, {"r-processing", jobProcessing},
		{"r-done", jobCompleted}, {"r-failed", jobFailed},
	} {
		seedJob(t, b, ctx, storage, tc.id, tc.st)
	}

	require.NoError(t, b.initializeBackend(ctx, &logical.InitializationRequest{Storage: storage}))

	for _, id := range []string{"r-pending", "r-processing"} {
		done := waitForJob(t, b, storage, id)
		require.Equal(t, jobCompleted, done.Status, "job %s 应恢复收敛", id)
	}
	// completed 的快照不被重驱动改写
	item, err := storage.Get(ctx, storageKeyJobs+"r-done")
	require.NoError(t, err)
	var j jobEntry
	require.NoError(t, item.DecodeJSON(&j))
	require.Equal(t, "CERT", j.Cert.CertificatePEM, "completed 不得被重驱动")
	// failed 保持终态
	item, err = storage.Get(ctx, storageKeyJobs+"r-failed")
	require.NoError(t, err)
	var jf jobEntry
	require.NoError(t, item.DecodeJSON(&jf))
	require.Equal(t, jobFailed, jf.Status)

	// Clean 链可调用（cancel 不 panic；renewer 的 prev Clean 为 nil 时也安全）
	require.NotNil(t, b.Clean)
	b.Clean(ctx)
}

// TestE2EAsyncIssuanceAndReuse（pebble，缺失 Skip）：异步提交→轮询→取证；
// 泛域名签发后单域请求覆盖复用（spec §5 端到端）。
func TestE2EAsyncIssuanceAndReuse(t *testing.T) {
	b, storage, _ := setupObtainable(t)
	ctx := context.Background()
	// 关闭 fake 注入，走真实 Obtain（setupObtainable 未注入 issueFn，显式置空防呆）
	b.issueFn = nil

	// 1) 异步签发 *.example.com（role 允许子域/裸域，泛域名按 bare 语义放行）
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web", Storage: storage,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"common_name": "*.example.com"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "异步提交应成功: %v", resp)
	require.NotEmpty(t, resp.Data["job_id"])
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
	require.Equal(t, done.Cert.CertificatePEM, resp2.Data["certificate"],
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
