package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathCerts(b *backend) []*framework.Path {
	return []*framework.Path{{
		Pattern: "certs/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role":              {Type: framework.TypeString, Description: "role 名。"},
			"common_name":            {Type: framework.TypeString, Required: true, Description: "主域名（可含通配符 *.）。"},
			"alternative_names":      {Type: framework.TypeCommaStringSlice, Description: "附加域名。"},
			"alt_names":              {Type: framework.TypeCommaStringSlice, Description: "附加域名别名 (同 alternative_names)。"},
			"sync":                   {Type: framework.TypeBool, Description: "同步等待签发完成（v0.1.0 兼容）。默认 false：异步返回 job_id。"},
			"skip_propagation_check": {Type: framework.TypeBool, Description: "单次签发覆盖：跳过 lego 本地 DNS 传播预检。"},
			"propagation_wait":       {Type: framework.TypeDurationSecond, Description: "单次签发覆盖：DNS 写入后的等待秒数。"},
			"resolvers":              {Type: framework.TypeCommaStringSlice, Description: "单次签发覆盖：自定义递归 DNS 服务器列表（如 223.5.5.5:53）。"},
		},
		ExistenceCheck: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
			role, err := b.getRole(ctx, req.Storage, d.Get("role").(string))
			return role != nil, err
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathIssueCert},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathIssueCert},
		},
	}}
}

// dns01Overrides 包含单次签发请求对 DNS-01 预检策略的临时覆盖。
type dns01Overrides struct {
	SkipPropagationCheck *bool
	PropagationWait      *int
	Resolvers            []string
}

// buildRoutes：按 account.dns_providers 顺序实时读凭据并构造子 provider，
// 同时聚合各条目的传播预检策略与单次请求的 overrides。
func (b *backend) buildRoutes(ctx context.Context, req *logical.Request, acc *accountEntry, ov *dns01Overrides) (*routingProvider, []dns01.ChallengeOption, error) {
	routes := make([]providerRoute, 0, len(acc.DNSProviders))
	var extraOpts []dns01.ChallengeOption

	// 聚合解析服务器与预检参数
	var (
		aggregatedResolvers []string
		skipCheck           bool
		hasSkipCheck        bool
		maxWait             int
	)

	for _, ref := range acc.DNSProviders {
		dp, err := b.getDNSProvider(ctx, req.Storage, ref.Name)
		if err != nil {
			return nil, nil, err
		}
		if dp == nil {
			return nil, nil, fmt.Errorf("dns-provider %q 不存在", ref.Name)
		}
		if dp.CredentialsRef == nil {
			return nil, nil, fmt.Errorf("dns-provider %q 缺少 credentials_ref", ref.Name)
		}
		raw, err := b.credLoader.Load(ctx, req.ClientToken, *dp.CredentialsRef)
		if err != nil {
			return nil, nil, fmt.Errorf("dns-provider %q 凭据读取失败: %w", ref.Name, err)
		}
		provider, err := newProvider(ctx, dp.Type, providerOpts{
			PropagationTimeout: dp.PropagationTimeout,
			PollingInterval:    dp.PollingInterval,
		}, resolveKeys(raw, *dp.CredentialsRef, envNames[dp.Type]))
		if err != nil {
			return nil, nil, fmt.Errorf("dns-provider %q: %w", ref.Name, err)
		}
		routes = append(routes, providerRoute{Name: ref.Name, Zones: ref.Zones, Provider: provider})

		if dp.SkipPropagationCheck {
			skipCheck = true
			hasSkipCheck = true
		}
		if dp.PropagationWait > maxWait {
			maxWait = dp.PropagationWait
		}
		if len(dp.Resolvers) > 0 {
			aggregatedResolvers = append(aggregatedResolvers, dp.Resolvers...)
		}
	}

	// 检查单次 overrides
	if ov != nil {
		if ov.SkipPropagationCheck != nil {
			skipCheck = *ov.SkipPropagationCheck
			hasSkipCheck = true
		}
		if ov.PropagationWait != nil {
			maxWait = *ov.PropagationWait
		}
		if len(ov.Resolvers) > 0 {
			aggregatedResolvers = ov.Resolvers
		}
	}

	if len(aggregatedResolvers) > 0 {
		dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{
			RecursiveNameservers: aggregatedResolvers,
		}))
	}
	if hasSkipCheck && skipCheck {
		extraOpts = append(extraOpts, dns01.PropagationWait(time.Duration(maxWait)*time.Second, true))
	} else if maxWait > 0 {
		extraOpts = append(extraOpts, dns01.PropagationWait(time.Duration(maxWait)*time.Second, false))
	}

	router, err := newRoutingProvider(routes)
	if err != nil {
		return nil, nil, err
	}
	return router, extraOpts, nil
}

func (b *backend) pathIssueCert(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	cn := d.Get("common_name").(string)
	if cn == "" {
		return logical.ErrorResponse("common_name 必填"), nil
	}
	alt := d.Get("alternative_names").([]string)
	if len(alt) == 0 {
		if a, ok := d.GetOk("alt_names"); ok {
			alt = a.([]string)
		}
	}
	domains := append([]string{cn}, alt...)

	if err := validateNames(cn, alt, role); err != nil {
		return logical.ErrorResponse("%v", err), nil
	}
	account, err := b.getAccount(ctx, req.Storage, role.Account)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return logical.ErrorResponse("account %q 不存在", role.Account), nil
	}

	key := cacheKey(role, domains)
	// 1) 缓存命中且未到期（certNeedsRenewal=false）→ Users++ 直接返回；
	//    已到期缓存视为 miss，落入下方重签。
	if !role.DisableCache {
		entry, err := b.cacheGet(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if entry != nil && !certNeedsRenewal(entry.CertificatePEM, role.CacheForRatio) {
			// Users++ 的读改写必须在单临界区完成（cacheUpdate），否则并发
			// 命中同 key 会丢失更新（应 N+2 得 N+1）。
			// 已知一次性微竞争：此刻若有并发重签以新证书覆写条目，下方响应
			// 仍会展示读取到的旧证书——窗口极短且仅影响本次响应内容，下一次
			// 命中即取到新证书，设计上容忍（Task 12 Renew 同理）。
			err := b.cacheUpdate(ctx, req.Storage, key, func(e *cacheEntry) *cacheEntry {
				e.Users++
				return e
			})
			if err != nil {
				return nil, err
			}
			resp, err := b.respondWithCert(ctx, req, roleName, role, entry, key, false, "")
			if err != nil {
				// 与新鲜签发路径一致：包装为错误响应（而非裸 error）。
				return logical.ErrorResponse("签发失败: %v", err), nil
			}
			resp.Data["reused"] = true
			return resp, nil
		}
	}

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

	// 1.8) 解析 DNS-01 覆盖参数
	var ov *dns01Overrides
	if v, ok := d.GetOk("skip_propagation_check"); ok {
		b := v.(bool)
		if ov == nil {
			ov = &dns01Overrides{}
		}
		ov.SkipPropagationCheck = &b
	}
	if v, ok := d.GetOk("propagation_wait"); ok {
		w := v.(int)
		if ov == nil {
			ov = &dns01Overrides{}
		}
		ov.PropagationWait = &w
	}
	if v, ok := d.GetOk("resolvers"); ok {
		res := v.([]string)
		if len(res) > 0 {
			if ov == nil {
				ov = &dns01Overrides{}
			}
			ov.Resolvers = res
		}
	}

	// 1.9) 默认异步：挂靠同 (role, domains) 的未完成 job，或创建新 job 由
	//      后台 Worker 驱动（spec §3）。validateNames/account 校验已前置完成。
	if !d.Get("sync").(bool) {
		return b.submitJobWithOverrides(ctx, req, roleName, role, cn, domains, ov)
	}

	// 2) sync=true：v0.1.0 同步契约。singleflight 防并发同 key 重复签发。executed 标记本调用者是否为
	//    领导者（闭包内设置，等待者经 WaitGroup happens-before 可见）：
	//    领导者的 lease 引用即 doIssue 写入的初始 Users=1；等待者共享同一
	//    响应并各自建 lease，返回前须经 waiterRefAdd 补自增，否则任一 lease
	//    撤销即提前归零、误删条目并真撤销兄弟 lease 仍在用的证书。
	executed := false
	v, err, _ := b.issueGroup.Do(key, func() (interface{}, error) {
		executed = true
		return b.doIssue(ctx, req, roleName, role, account, cn, domains, key, ov)
	})
	if err != nil {
		return logical.ErrorResponse("签发失败: %v", err), nil
	}
	resp, ok := v.(*logical.Response)
	if !ok || resp == nil {
		return nil, fmt.Errorf("签发内部错误：意外的 singleflight 结果 %T", v)
	}
	if !executed {
		// 签发成功但本调用者（等待者）未能建立引用：报错让调用方重试——
		// 重试将命中新鲜缓存走 Users++ 命中路径，自愈。
		if uerr := b.waiterRefAdd(ctx, req.Storage, key); uerr != nil {
			return logical.ErrorResponse("签发失败: %v", uerr), nil
		}
	}
	return resp, nil
}

// obtainCert：路由→实时凭据→provider→一次完整 ACME Obtain。issueFn 非空时
// （测试注入）直接替代；错误文案与同步路径历史行为一致。
func (b *backend) obtainCert(ctx context.Context, req *logical.Request, account *accountEntry, domains []string, ov *dns01Overrides) (*certificate.Resource, error) {
	if b.issueFn != nil {
		return b.issueFn(ctx, req, account, domains)
	}
	router, extraOpts, err := b.buildRoutes(ctx, req, account, ov)
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
func (b *backend) doIssue(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, account *accountEntry, cn string, domains []string, key string, ov *dns01Overrides) (*logical.Response, error) {
	res, err := b.obtainCert(ctx, req, account, domains, ov)
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
	if !role.DisableCache {
		// disable_cache：纯直通不落缓存（也无引用计数）——否则同 key 二次
		// 签发会以 Users=1 覆写已有条目，破坏 Users==lease 数不变式：首个
		// lease 撤销即归零误删条目，并向 ACME 真撤销兄弟 lease 仍在用的证书。
		// （I-1）
		if err := b.cachePut(ctx, req.Storage, key, entry); err != nil {
			return nil, err
		}
	}
	return b.respondWithCert(ctx, req, roleName, role, entry, key, true, "")
}

// respondWithCert：组装响应（含证书有效期）+ MaxTTL=证书剩余寿命。
// freshIssue=true（新鲜签发路径）：先写 KV 输出（未配置则 no-op），失败时
// 删除缓存条目后报错，调用者重试走完整重签。
// freshIssue=false（缓存命中路径）：纯读不写 KV（spec §7「缓存命中不重写」
// ——命中重写会膨胀 KVv2 历史，且 KV 故障时会误删 Users≥2 的共享条目，KV
// 持续故障期间还会反复触发完整 ACME Obtain 暴露限流）；kvPathOverride 非空
// 时（覆盖复用）以其为 output_path（指向签发 role 名下真实写入位置），
// 否则按请求 role 的 output_kv_mount 推导。
func (b *backend) respondWithCert(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, entry *cacheEntry, key string, freshIssue bool, kvPathOverride string) (*logical.Response, error) {
	kvPath := ""
	if freshIssue {
		var err error
		kvPath, err = b.writeCertOutput(ctx, req, roleName, role, entry.CN, entry)
		if err != nil {
			// 不变式：签发成功+KV 成功 = Users=1 = lease 数。KV 失败时响应无
			// Secret、core 不会建 lease，残留条目（Users≥1）将无人释放成为孤儿
			// 引用（重试命中路径还会继续 +1）。整条删除后重试完整重签，代价是
			// 多一次 ACME Obtain，可接受。disable_cache 角色本就无条目（I-1），
			// 先确认存在再删除，miss 时跳过。
			if existing, gerr := b.cacheGet(ctx, req.Storage, key); gerr == nil && existing != nil {
				if delErr := b.cacheDelete(ctx, req.Storage, key); delErr != nil {
					return nil, fmt.Errorf("KV 输出失败: %w（且缓存清理失败: %v）", err, delErr)
				}
			}
			return nil, fmt.Errorf("KV 输出失败: %w", err)
		}
	} else if kvPathOverride != "" {
		// 覆盖复用：output_path 以签发 role 名下的既有 KV 数据为准（spec §5.3）。
		kvPath = kvPathOverride
	} else if role.OutputKVMount != "" {
		// 命中路径不重写 KV：output_path 指向签发时已写入的既有数据。
		kvPath = outputKVPath(roleName, entry.CN)
	}
	notBefore, notAfter := certValidity(entry.CertificatePEM)
	resp := b.issueResponse(entry, key, role.Account, roleName, kvPath)
	if !notAfter.IsZero() {
		// 有效期以 RFC3339 字符串输出，与 KV 输出（writeCertOutput）语义一致。
		resp.Data["not_before"] = notBefore.Format(time.RFC3339)
		resp.Data["not_after"] = notAfter.Format(time.RFC3339)
		// 剩余寿命即最大租期；Renew（Task 12）据此在到期前续期。
		resp.Secret.LeaseOptions.MaxTTL = time.Until(notAfter)
	}
	return resp, nil
}

// certValidity 解析证书有效期（UTC）；解析失败返回零值。
func certValidity(certPEM string) (time.Time, time.Time) {
	if cert, err := certcrypto.ParsePEMCertificate([]byte(certPEM)); err == nil {
		return cert.NotBefore.UTC(), cert.NotAfter.UTC()
	}
	return time.Time{}, time.Time{}
}

// issueResponse 组装签发/缓存命中响应；InternalData 供 Renew/Revoke 定位
// 缓存条目与账户，不含敏感值。secret_type 是 framework 路由续期/撤销回调的
// 依据（sdk v2.6.2 的 logical.Secret 无 Type 字段，以 InternalData 承载）。
func (b *backend) issueResponse(entry *cacheEntry, key, account, role, kvPath string) *logical.Response {
	data := map[string]interface{}{
		"common_name":     entry.CN,
		"domains":         entry.Domains,
		"certificate":     entry.CertificatePEM,
		"private_key":     entry.PrivateKeyPEM,
		"issuer_cert":     entry.IssuerCertificatePEM,
		"url":             entry.CertURL,
		"cert_stable_url": entry.CertStableURL,
	}
	if kvPath != "" {
		data["output_path"] = kvPath
	}
	resp := &logical.Response{Data: data}
	resp.Secret = &logical.Secret{
		LeaseOptions: logical.LeaseOptions{
			// core 依响应里的 Renewable 建 lease；为 false 则 lease 不可续、
			// certRenew 永不触发。TTL 留空由 core 套默认租期，MaxTTL 随后
			// 在 respondWithCert 中绑定证书剩余寿命。
			Renewable: true,
		},
		InternalData: map[string]interface{}{
			"secret_type": secretCertType,
			"account":     account,
			"cache_key":   key,
			"role":        role,
		},
	}
	return resp
}
