package acme

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// resumeJobs 由 InitializeFunc（Backend 构造时设置）在挂载/重启后触发；
// 直接调用 Backend() 的单测路径无人调 Initialize，恢复逻辑对既有测试零影响。

const storageKeyJobs = "jobs/"

type jobStatus = api.JobStatus

const (
	jobPending    = api.JobPending
	jobProcessing = api.JobProcessing
	jobCompleted  = api.JobCompleted
	jobFailed     = api.JobFailed
)

type jobCertSnapshot = api.JobCertSnapshot

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

	// 单次 Issue 请求传入的覆盖配置（持久化，重启恢复时保持生效）
	SkipPropagationCheck *bool    `json:"skip_propagation_check,omitempty"`
	PropagationWait      *int     `json:"propagation_wait,omitempty"`
	Resolvers            []string `json:"resolvers,omitempty"`
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

	// 合成请求：真实 apiCredentialLoader/apiKVWriter 忽略 ClientToken（以
	// 插件服务身份执行）；非空占位仅为满足测试 fake 的防误用断言。
	workerReq := &logical.Request{Storage: st, ClientToken: "job-worker"}

	var ov *dns01Overrides
	if job.SkipPropagationCheck != nil || job.PropagationWait != nil || len(job.Resolvers) > 0 {
		ov = &dns01Overrides{
			SkipPropagationCheck: job.SkipPropagationCheck,
			PropagationWait:      job.PropagationWait,
			Resolvers:            job.Resolvers,
		}
	}

	res, err := b.obtainCert(ctx, workerReq, account, job.Domains, ov)
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
	kvPath, err := b.writeCertOutput(ctx, workerReq, job.Role, role, entry.CN, entry)
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
	// 结果已入缓存/KV；快照写失败仅影响 GET jobs 可见性，下次重启扫描时
	// 该 job 仍为 processing，会被重新驱动一次（幂等）。
	_ = b.jobUpdate(ctx, st, job)
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
	return b.submitJobWithOverrides(ctx, req, roleName, role, cn, domains, nil)
}

func (b *backend) submitJobWithOverrides(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, cn string, domains []string, ov *dns01Overrides) (*logical.Response, error) {
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
	if ov != nil {
		job.SkipPropagationCheck = ov.SkipPropagationCheck
		job.PropagationWait = ov.PropagationWait
		job.Resolvers = ov.Resolvers
	}
	if err := b.jobUpdate(ctx, req.Storage, job); err != nil {
		return nil, err
	}
	// Worker 用副本驱动：避免与父请求读取 jobResponse 并发改写同一结构。
	workerJob := *job
	go b.runJob(b.workerCtx(), req.Storage, &workerJob)
	return b.jobResponse(job), nil
}

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
