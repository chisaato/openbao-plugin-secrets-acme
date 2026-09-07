package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathCertsExtended 为 certs 路径增加 LIST、GET /certs/{role}/{cn}、DELETE (Revoke)、RENEW 处理。
func pathCertsExtended(b *backend) []*framework.Path {
	return []*framework.Path{
		// 1. LIST certs/? 或 LIST certs/
		{
			Pattern: "certs/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Summary:  "列出全部已签发或缓存的证书",
					Callback: b.pathCertListAll,
				},
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "列出全部已签发或缓存的证书",
					Callback: b.pathCertListAll,
				},
			},
		},
		// 2. LIST certs/{role}/?
		{
			Pattern: "certs/" + framework.GenericNameRegex("role") + "/list/?$",
			Fields: map[string]*framework.FieldSchema{
				"role": {Type: framework.TypeString, Description: "Role 名称"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Summary:  "列出指定 Role 下的证书",
					Callback: b.pathCertListByRole,
				},
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "列出指定 Role 下的证书",
					Callback: b.pathCertListByRole,
				},
			},
		},
		// 3. POST certs/{role}/{cn}/renew
		{
			Pattern: "certs/" + framework.GenericNameRegex("role") + "/" + framework.MatchAllRegex("cn") + "/renew$",
			Fields: map[string]*framework.FieldSchema{
				"role": {Type: framework.TypeString, Description: "Role 名称"},
				"cn":   {Type: framework.TypeString, Description: "证书 CommonName 或主域名"},
				"sync": {Type: framework.TypeBool, Description: "是否同步阻塞等待续签完成"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Summary:  "主动触发证书续签",
					Callback: b.pathCertRenewExplicit,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "主动触发证书续签",
					Callback: b.pathCertRenewExplicit,
				},
			},
		},
		// 4. GET/DELETE certs/{role}/{cn}
		{
			Pattern: "certs/" + framework.GenericNameRegex("role") + "/" + framework.MatchAllRegex("cn") + "$",
			Fields: map[string]*framework.FieldSchema{
				"role": {Type: framework.TypeString, Description: "Role 名称"},
				"cn":   {Type: framework.TypeString, Description: "证书 CommonName 或主域名"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "获取指定证书详情",
					Callback: b.pathCertGet,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Summary:  "撤销并删除证书 (向 CA 发起 Revoke 并清理缓存)",
					Callback: b.pathCertRevoke,
				},
			},
		},
	}
}

// certSummary 表示 LIST 时的摘要条目
type certSummary struct {
	CommonName string   `json:"common_name"`
	Domains    []string `json:"domains"`
	Role       string   `json:"role"`
	Account    string   `json:"account"`
	NotBefore  string   `json:"not_before,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
	CacheKey   string   `json:"cache_key"`
}

func parseCertDates(certPEM string) (string, string) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", ""
	}
	return cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339)
}

func (b *backend) pathCertListAll(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, storageKeyCache)
	if err != nil {
		return nil, err
	}

	var results []certSummary
	var cnList []string
	for _, k := range keys {
		entry, err := b.cacheGet(ctx, req.Storage, k)
		if err != nil || entry == nil {
			continue
		}
		nb, na := parseCertDates(entry.CertificatePEM)
		results = append(results, certSummary{
			CommonName: entry.CN,
			Domains:    entry.Domains,
			Role:       entry.Role,
			Account:    entry.Account,
			NotBefore:  nb,
			NotAfter:   na,
			CacheKey:   k,
		})
		cnList = append(cnList, entry.CN)
	}

	resp := logical.ListResponse(cnList)
	if resp.Data == nil {
		resp.Data = make(map[string]any)
	}
	resp.Data["certificates"] = results
	return resp, nil
}

func (b *backend) pathCertListByRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	targetRole := d.Get("role").(string)
	keys, err := req.Storage.List(ctx, storageKeyCache)
	if err != nil {
		return nil, err
	}

	var results []certSummary
	var cnList []string
	for _, k := range keys {
		entry, err := b.cacheGet(ctx, req.Storage, k)
		if err != nil || entry == nil {
			continue
		}
		if entry.Role != targetRole {
			continue
		}
		nb, na := parseCertDates(entry.CertificatePEM)
		results = append(results, certSummary{
			CommonName: entry.CN,
			Domains:    entry.Domains,
			Role:       entry.Role,
			Account:    entry.Account,
			NotBefore:  nb,
			NotAfter:   na,
			CacheKey:   k,
		})
		cnList = append(cnList, entry.CN)
	}

	resp := logical.ListResponse(cnList)
	if resp.Data == nil {
		resp.Data = make(map[string]any)
	}
	resp.Data["certificates"] = results
	return resp, nil
}

// findCertEntryByRoleCN 在 cache 中查找匹配 role 和 cn 的证书条目
func (b *backend) findCertEntryByRoleCN(ctx context.Context, s logical.Storage, roleName, cn string) (*cacheEntry, string, error) {
	keys, err := s.List(ctx, storageKeyCache)
	if err != nil {
		return nil, "", err
	}

	for _, k := range keys {
		entry, err := b.cacheGet(ctx, s, k)
		if err != nil || entry == nil {
			continue
		}
		if strings.EqualFold(entry.Role, roleName) && strings.EqualFold(entry.CN, cn) {
			return entry, k, nil
		}
	}
	return nil, "", nil
}

func (b *backend) pathCertGet(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	cn := d.Get("cn").(string)

	entry, key, err := b.findCertEntryByRoleCN(ctx, req.Storage, roleName, cn)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil // 404
	}

	nb, na := parseCertDates(entry.CertificatePEM)
	role, _ := b.getRole(ctx, req.Storage, roleName)
	needsRenew := false
	if role != nil {
		needsRenew = certNeedsRenewal(entry.CertificatePEM, role.CacheForRatio)
	}

	return &logical.Response{
		Data: map[string]any{
			"common_name":      entry.CN,
			"domains":          entry.Domains,
			"role":             entry.Role,
			"account":          entry.Account,
			"certificate":      entry.CertificatePEM,
			"private_key":      entry.PrivateKeyPEM,
			"issuer_cert":      entry.IssuerCertificatePEM,
			"url":              entry.CertURL,
			"cert_stable_url":  entry.CertStableURL,
			"not_before":       nb,
			"not_after":        na,
			"needs_renewal":    needsRenew,
			"cache_key":        key,
		},
	}, nil
}

func (b *backend) pathCertRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	cn := d.Get("cn").(string)

	entry, key, err := b.findCertEntryByRoleCN(ctx, req.Storage, roleName, cn)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	// 1. 尝试向 CA 真撤销
	if account, aerr := b.getAccount(ctx, req.Storage, entry.Account); aerr == nil && account != nil {
		if user, uerr := account.legoUser(); uerr == nil {
			if client, cerr := newLegoClient(user, account.ServerURL, account.InsecureTLS); cerr == nil {
				_ = client.Certificate.Revoke(ctx, []byte(entry.CertificatePEM))
			}
		}
	}

	// 2. 从 cache 中删除
	if err := b.cacheDelete(ctx, req.Storage, key); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"revoked":     true,
			"common_name": entry.CN,
			"role":        entry.Role,
		},
	}, nil
}

func (b *backend) pathCertRenewExplicit(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	cn := d.Get("cn").(string)
	syncFlag := d.Get("sync").(bool)

	entry, _, err := b.findCertEntryByRoleCN(ctx, req.Storage, roleName, cn)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("未找到要续订的证书 %s/%s", roleName, cn), nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q 不存在", roleName), nil
	}

	// 触发签发：如果非 sync 则直接提交 job
	if !syncFlag {
		return b.submitJob(ctx, req, roleName, role, entry.CN, entry.Domains)
	}

	account, err := b.getAccount(ctx, req.Storage, role.Account)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return logical.ErrorResponse("account %q 不存在", role.Account), nil
	}

	key := cacheKey(role, entry.Domains)
	v, err, _ := b.issueGroup.Do(key, func() (any, error) {
		return b.doIssue(ctx, req, roleName, role, account, entry.CN, entry.Domains, key, nil)
	})
	if err != nil {
		return logical.ErrorResponse("续订失败: %v", err), nil
	}
	resp, ok := v.(*logical.Response)
	if !ok || resp == nil {
		return nil, fmt.Errorf("续订内部错误")
	}
	return resp, nil
}
