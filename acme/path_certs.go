package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathCerts(b *backend) []*framework.Path {
	return []*framework.Path{{
		Pattern: "certs/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role":              {Type: framework.TypeString, Description: "role 名。"},
			"common_name":       {Type: framework.TypeString, Required: true, Description: "主域名（可含通配符 *.）。"},
			"alternative_names": {Type: framework.TypeCommaStringSlice, Description: "附加域名。"},
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

// buildRoutes：按 account.dns_providers 顺序实时读凭据并构造子 provider。
// 凭据仅在请求生命周期内存在，不落存储、不进日志、不进响应。
func (b *backend) buildRoutes(ctx context.Context, req *logical.Request, acc *accountEntry) (*routingProvider, error) {
	routes := make([]providerRoute, 0, len(acc.DNSProviders))
	for _, ref := range acc.DNSProviders {
		dp, err := b.getDNSProvider(ctx, req.Storage, ref.Name)
		if err != nil {
			return nil, err
		}
		if dp == nil {
			return nil, fmt.Errorf("dns-provider %q 不存在", ref.Name)
		}
		if dp.CredentialsRef == nil {
			return nil, fmt.Errorf("dns-provider %q 缺少 credentials_ref", ref.Name)
		}
		raw, err := b.credLoader.Load(ctx, req.ClientToken, *dp.CredentialsRef)
		if err != nil {
			return nil, fmt.Errorf("dns-provider %q 凭据读取失败: %w", ref.Name, err)
		}
		provider, err := newProvider(ctx, dp.Type, providerOpts{
			PropagationTimeout: dp.PropagationTimeout,
			PollingInterval:    dp.PollingInterval,
		}, resolveKeys(raw, *dp.CredentialsRef, envNames[dp.Type]))
		if err != nil {
			return nil, fmt.Errorf("dns-provider %q: %w", ref.Name, err)
		}
		routes = append(routes, providerRoute{Name: ref.Name, Zones: ref.Zones, Provider: provider})
	}
	return newRoutingProvider(routes)
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
			entry.Users++
			if err := b.cachePut(ctx, req.Storage, key, entry); err != nil {
				return nil, err
			}
			return b.respondWithCert(ctx, req, roleName, role, entry, key)
		}
	}

	// 2) singleflight 防并发同 key 重复签发；条目读改写由 cacheMu 串行化。
	v, err, _ := b.issueGroup.Do(key, func() (interface{}, error) {
		return b.doIssue(ctx, req, roleName, role, account, cn, domains, key)
	})
	if err != nil {
		return logical.ErrorResponse("签发失败: %v", err), nil
	}
	resp, ok := v.(*logical.Response)
	if !ok || resp == nil {
		return nil, fmt.Errorf("签发内部错误：意外的 singleflight 结果 %T", v)
	}
	return resp, nil
}

// doIssue：路由→实时凭据→provider→Obtain→缓存→KV 输出→响应。
func (b *backend) doIssue(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, account *accountEntry, cn string, domains []string, key string) (*logical.Response, error) {
	router, err := b.buildRoutes(ctx, req, account)
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
	if err := client.Challenge.SetDNS01Provider(dns01Provider); err != nil {
		return nil, fmt.Errorf("设置 DNS-01 provider: %w", err)
	}

	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("ACME obtain: %w", err)
	}

	entry := &cacheEntry{
		Users:                1,
		Account:              account.Name,
		CN:                   cn,
		Domains:              domains,
		CertURL:              res.CertURL,
		CertStableURL:        res.CertStableURL,
		PrivateKeyPEM:        string(res.PrivateKey),
		CertificatePEM:       string(res.Certificate),
		IssuerCertificatePEM: string(res.IssuerCertificate),
	}
	if err := b.cachePut(ctx, req.Storage, key, entry); err != nil {
		return nil, err
	}
	return b.respondWithCert(ctx, req, roleName, role, entry, key)
}

// respondWithCert：KV 输出（未配置则 no-op）+ 组装响应 + MaxTTL=证书剩余寿命。
// 新鲜签发与缓存命中共用：签发成功但 KV 输出失败时证书已缓存，调用者重试
// 会命中本路径补写输出。
func (b *backend) respondWithCert(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, entry *cacheEntry, key string) (*logical.Response, error) {
	kvPath, err := b.writeCertOutput(ctx, req, roleName, role, entry.CN, entry)
	if err != nil {
		return nil, fmt.Errorf("KV 输出失败: %w", err)
	}
	resp := b.issueResponse(entry, key, role.Account, kvPath)
	if _, notAfter := certValidity(entry.CertificatePEM); !notAfter.IsZero() {
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

// issueResponse 组装签发/缓存命中响应；InternalData 供 Renew/Revoke（Task 12）
// 定位缓存条目与账户，不含敏感值。
func (b *backend) issueResponse(entry *cacheEntry, key, account, kvPath string) *logical.Response {
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
	resp.Secret = &logical.Secret{InternalData: map[string]interface{}{
		"account":   account,
		"cache_key": key,
	}}
	return resp
}
