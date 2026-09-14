package acme

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
		// 4. POST certs/{role}/{cn}/kv/sync：手动触发一次 KV 投影拷贝
		{
			Pattern: "certs/" + framework.GenericNameRegex("role") + "/" + framework.MatchAllRegex("cn") + "/kv/sync$",
			Fields: map[string]*framework.FieldSchema{
				"role":  {Type: framework.TypeString, Description: "Role 名称"},
				"cn":    {Type: framework.TypeString, Description: "证书 CommonName 或主域名"},
				"force": {Type: framework.TypeBool, Description: "强制覆盖：跳过 KV 占用检查直接写入"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Summary:  "手动触发一次证书 KV 投影拷贝",
					Callback: b.pathCertKVSync,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "手动触发一次证书 KV 投影拷贝",
					Callback: b.pathCertKVSync,
				},
			},
		},
		// 5. POST certs/{role}/{cn}/kv/link：建立/覆盖绑定并立即 sync 一次
		{
			Pattern: "certs/" + framework.GenericNameRegex("role") + "/" + framework.MatchAllRegex("cn") + "/kv/link$",
			Fields: map[string]*framework.FieldSchema{
				"role":  {Type: framework.TypeString, Description: "Role 名称"},
				"cn":    {Type: framework.TypeString, Description: "证书 CommonName 或主域名"},
				"mount": {Type: framework.TypeString, Description: "KV mount；缺省取 role 的 output_kv_mount"},
				"path":  {Type: framework.TypeString, Description: "mount 内的数据路径 override；空=派生 certs/{certID}"},
				"force": {Type: framework.TypeBool, Description: "强制覆盖：跳过 KV 占用检查直接写入"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Summary:  "绑定证书 KV 输出位置并立即同步一次",
					Callback: b.pathCertKVLink,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "绑定证书 KV 输出位置并立即同步一次",
					Callback: b.pathCertKVLink,
				},
			},
		},
		// 6. POST certs/{role}/{cn}/kv/unlink：解除绑定（可选删除已投影数据）
		{
			Pattern: "certs/" + framework.GenericNameRegex("role") + "/" + framework.MatchAllRegex("cn") + "/kv/unlink$",
			Fields: map[string]*framework.FieldSchema{
				"role":      {Type: framework.TypeString, Description: "Role 名称"},
				"cn":        {Type: framework.TypeString, Description: "证书 CommonName 或主域名"},
				"delete_kv": {Type: framework.TypeBool, Description: "是否删除已投影的 KV 数据"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Summary:  "解除证书 KV 输出绑定",
					Callback: b.pathCertKVUnlink,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Summary:  "解除证书 KV 输出绑定",
					Callback: b.pathCertKVUnlink,
				},
			},
		},
		// 7. GET/DELETE certs/id/{id} (直接通过 Cert ID / CacheKey 检索，毫无歧义)
		{
			Pattern: "certs/id/" + framework.GenericNameRegex("id") + "$",
			Fields: map[string]*framework.FieldSchema{
				"id": {Type: framework.TypeString, Description: "证书唯一标识 CacheKey / Cert ID"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Summary:  "通过 Cert ID 获取指定证书详情",
					Callback: b.pathCertGetByID,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Summary:  "通过 Cert ID 撤销并删除指定证书",
					Callback: b.pathCertRevokeByID,
				},
			},
		},
		// 5. GET/DELETE certs/{role}/{cn}
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
	ID             string   `json:"id"`
	CertID         string   `json:"cert_id"`
	CacheKey       string   `json:"cache_key"`
	CommonName     string   `json:"common_name"`
	Domains        []string `json:"domains"`
	Role           string   `json:"role"`
	Account        string   `json:"account"`
	OutputKVStatus string   `json:"output_kv_status,omitempty"`
	OutputKVPath   string   `json:"output_kv_path,omitempty"`
	NotBefore      string   `json:"not_before,omitempty"`
	NotAfter       string   `json:"not_after,omitempty"`
}

// resolveOutputKVPath：展示用完整 KV 路径。条目记录的 OutputKVPath 优先；旧条目
// 未记录但 Mount 非空时现场回退拼接 mount + certs/{certID}；均无则空串（不展示）。
func resolveOutputKVPath(entry *cacheEntry, certID string) string {
	if entry.OutputKVPath != "" {
		return entry.OutputKVPath
	}
	if entry.OutputKVMount != "" {
		return entry.OutputKVMount + "/" + outputKVPath(certID)
	}
	return ""
}

// outputKVFields 组装 KV 投影展示字段：mount/path 仅在记录 mount 非空时输出，
// status 恒输出（可能为空串）。
func outputKVFields(entry *cacheEntry, certID string) map[string]any {
	fields := map[string]any{"output_kv_status": entry.OutputKVStatus}
	if entry.OutputKVMount != "" {
		fields["output_kv_mount"] = entry.OutputKVMount
	}
	if path := resolveOutputKVPath(entry, certID); path != "" {
		fields["output_kv_path"] = path
	}
	return fields
}

// resolveOutputKVMount：撤销清理的 mount 优先条目记录的最后成功写入位置，
// 为空时回退 role 现值（旧条目/兼容行为）。
func (b *backend) resolveOutputKVMount(ctx context.Context, s logical.Storage, entry *cacheEntry) string {
	if entry.OutputKVMount != "" {
		return entry.OutputKVMount
	}
	if entry.Role == "" {
		return ""
	}
	role, err := b.getRole(ctx, s, entry.Role)
	if err != nil || role == nil {
		return ""
	}
	return role.OutputKVMount
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
			ID:             k,
			CertID:         k,
			CacheKey:       k,
			CommonName:     entry.CN,
			Domains:        entry.Domains,
			Role:           entry.Role,
			Account:        entry.Account,
			OutputKVStatus: entry.OutputKVStatus,
			OutputKVPath:   resolveOutputKVPath(entry, k),
			NotBefore:      nb,
			NotAfter:       na,
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
			ID:             k,
			CertID:         k,
			CacheKey:       k,
			CommonName:     entry.CN,
			Domains:        entry.Domains,
			Role:           entry.Role,
			Account:        entry.Account,
			OutputKVStatus: entry.OutputKVStatus,
			OutputKVPath:   resolveOutputKVPath(entry, k),
			NotBefore:      nb,
			NotAfter:       na,
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

	data := map[string]any{
		"id":              key,
		"cert_id":         key,
		"common_name":     entry.CN,
		"domains":         entry.Domains,
		"role":            entry.Role,
		"account":         entry.Account,
		"certificate":     entry.CertificatePEM,
		"private_key":     entry.PrivateKeyPEM,
		"issuer_cert":     entry.IssuerCertificatePEM,
		"url":             entry.CertURL,
		"cert_stable_url": entry.CertStableURL,
		"not_before":      nb,
		"not_after":       na,
		"needs_renewal":   needsRenew,
		"cache_key":       key,
	}
	for k, v := range outputKVFields(entry, key) {
		data[k] = v
	}
	return &logical.Response{Data: data}, nil
}

// resolveCertByID 通过全量 ID 或前缀查找证书条目。
// 规则：
// 1. 若精确命中，直接返回；
// 2. 若前缀匹配（长度 >= 4）：
//   - 命中唯 1 个则返回；
//   - 命中 > 1 个返回歧义错误；
//   - 未命中返回 nil, "", nil (404)。
func (b *backend) resolveCertByID(ctx context.Context, s logical.Storage, queryID string) (*cacheEntry, string, error) {
	queryID = strings.TrimSpace(queryID)
	if queryID == "" {
		return nil, "", nil
	}

	// 1. 尝试精确查找
	entry, err := b.cacheGet(ctx, s, queryID)
	if err != nil {
		return nil, "", err
	}
	if entry != nil {
		return entry, queryID, nil
	}

	// 2. 若长度小于 4，为了防止过大范围模糊匹配碰撞，拒绝前缀查找
	if len(queryID) < 4 {
		return nil, "", nil
	}

	keys, err := s.List(ctx, storageKeyCache)
	if err != nil {
		return nil, "", err
	}

	var matchedKeys []string
	for _, k := range keys {
		if strings.HasPrefix(strings.ToLower(k), strings.ToLower(queryID)) {
			matchedKeys = append(matchedKeys, k)
		}
	}

	if len(matchedKeys) == 0 {
		return nil, "", nil
	}
	if len(matchedKeys) > 1 {
		return nil, "", fmt.Errorf("ambiguous cert ID prefix %q matches %d certificates", queryID, len(matchedKeys))
	}

	exactKey := matchedKeys[0]
	entry, err = b.cacheGet(ctx, s, exactKey)
	if err != nil {
		return nil, "", err
	}
	return entry, exactKey, nil
}

func (b *backend) pathCertGetByID(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	queryID := d.Get("id").(string)
	entry, certID, err := b.resolveCertByID(ctx, req.Storage, queryID)
	if err != nil {
		return logical.ErrorResponse("%v", err), nil
	}
	if entry == nil {
		return nil, nil // 404
	}

	nb, na := parseCertDates(entry.CertificatePEM)
	role, _ := b.getRole(ctx, req.Storage, entry.Role)
	needsRenew := false
	if role != nil {
		needsRenew = certNeedsRenewal(entry.CertificatePEM, role.CacheForRatio)
	}

	data := map[string]any{
		"id":              certID,
		"cert_id":         certID,
		"common_name":     entry.CN,
		"domains":         entry.Domains,
		"role":            entry.Role,
		"account":         entry.Account,
		"certificate":     entry.CertificatePEM,
		"private_key":     entry.PrivateKeyPEM,
		"issuer_cert":     entry.IssuerCertificatePEM,
		"url":             entry.CertURL,
		"cert_stable_url": entry.CertStableURL,
		"not_before":      nb,
		"not_after":       na,
		"needs_renewal":   needsRenew,
		"cache_key":       certID,
	}
	for k, v := range outputKVFields(entry, certID) {
		data[k] = v
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathCertRevokeByID(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	queryID := d.Get("id").(string)
	entry, certID, err := b.resolveCertByID(ctx, req.Storage, queryID)
	if err != nil {
		return logical.ErrorResponse("%v", err), nil
	}
	if entry == nil {
		return nil, nil
	}

	// 1. 尝试向 CA 真撤销
	if account, aerr := b.getAccount(ctx, req.Storage, entry.Account); aerr == nil && account != nil {
		if user, uerr := AccountLegoUser(account); uerr == nil {
			if client, cerr := newLegoClient(user, account.ServerURL, account.InsecureTLS); cerr == nil {
				_ = client.Certificate.Revoke(ctx, []byte(entry.CertificatePEM))
			}
		}
	}

	// 2. 从 cache 中删除
	if err := b.cacheDelete(ctx, req.Storage, certID); err != nil {
		return nil, err
	}

	// 3. 联动清理 KV 证书输出（尽力而为）：优先条目记录的最后成功写入位置。
	if mount := b.resolveOutputKVMount(ctx, req.Storage, entry); mount != "" {
		_ = b.deleteCertOutput(ctx, req.ClientToken, mount, certID, entry)
	}

	return &logical.Response{
		Data: map[string]any{
			"revoked":     true,
			"id":          certID,
			"common_name": entry.CN,
			"role":        entry.Role,
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
		if user, uerr := AccountLegoUser(account); uerr == nil {
			if client, cerr := newLegoClient(user, account.ServerURL, account.InsecureTLS); cerr == nil {
				_ = client.Certificate.Revoke(ctx, []byte(entry.CertificatePEM))
			}
		}
	}

	// 2. 从 cache 中删除
	if err := b.cacheDelete(ctx, req.Storage, key); err != nil {
		return nil, err
	}

	// 3. 联动清理 KV 证书输出（尽力而为）：优先条目记录的最后成功写入位置。
	if mount := b.resolveOutputKVMount(ctx, req.Storage, entry); mount != "" {
		_ = b.deleteCertOutput(ctx, req.ClientToken, mount, key, entry)
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
		return b.doIssue(ctx, req, roleName, role, account, entry.CN, entry.Domains, key, nil, kvPolicyBestEffort)
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

// kvWriteErrorResponse：把 writeCertOutput 的错误按仓库既有样式包装为错误响应，
// 冲突时提示 force 覆盖。
func kvWriteErrorResponse(action string, err error) *logical.Response {
	var conflict *kvConflictError
	if errors.As(err, &conflict) {
		return logical.ErrorResponse("%s被拒绝: %v（清理该 KV 条目，或使用 force=true 显式覆盖）", action, err)
	}
	return logical.ErrorResponse("%s失败: %v", action, err)
}

// validateKVPathOverride 校验 link 的 path override：空=派生（允许）；非空时
// 不得以 "/" 开头结尾、不得含 ".." 段、不得含空路径段。
func validateKVPathOverride(p string) error {
	if p == "" {
		return nil
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return fmt.Errorf("path 不得以 \"/\" 开头或结尾")
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "..":
			return fmt.Errorf("path 不得包含 \"..\" 段")
		case "":
			return fmt.Errorf("path 不得包含空路径段")
		}
	}
	return nil
}

// pathCertKVSync：单次 KV 投影拷贝。role 未配 output_kv_mount 且证书未 link
// 时报错；冲突默认 Enforce 拒绝，force=true 时 Overwrite。写入与条目持久化在同一
// cacheUpdate 临界区内完成。响应复用 outputKVFields 展示投影字段。
func (b *backend) pathCertKVSync(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	cn := d.Get("cn").(string)
	force := d.Get("force").(bool)

	entry, key, err := b.findCertEntryByRoleCN(ctx, req.Storage, roleName, cn)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil // 404
	}
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if effectiveOutputKVMount(role, entry) == "" {
		return logical.ErrorResponse("未配置 KV 输出：role 未设置 output_kv_mount 且证书未 link"), nil
	}

	policy := kvPolicyEnforce
	if force {
		policy = kvPolicyOverwrite
	}

	// writeCertOutput 失败时（Enforce 冲突/读失败/写失败）尚未就地改字段，
	// 回调原样返回 e；错误在临界区外统一包装为错误响应。
	var updated *cacheEntry
	var writeErr error
	if err := b.cacheUpdate(ctx, req.Storage, key, func(e *cacheEntry) *cacheEntry {
		_, writeErr = b.writeCertOutput(ctx, req, roleName, role, key, e, policy)
		updated = e
		return e
	}); err != nil {
		return nil, err
	}
	if writeErr != nil {
		return kvWriteErrorResponse("KV 同步", writeErr), nil
	}
	return &logical.Response{Data: outputKVFields(updated, key)}, nil
}

// pathCertKVLink：建立/覆盖绑定并立即 sync 一次。在 cacheUpdate 临界区内先写入
// link 字段再调 writeCertOutput；失败时回滚三个绑定字段，维持 Mount/Path=
// 最后成功写入位置不变式。mount 缺省取 role.OutputKVMount。
func (b *backend) pathCertKVLink(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	cn := d.Get("cn").(string)
	mount := d.Get("mount").(string)
	pathOverride := d.Get("path").(string)
	force := d.Get("force").(bool)

	entry, key, err := b.findCertEntryByRoleCN(ctx, req.Storage, roleName, cn)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil // 404
	}
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if mount == "" && role != nil {
		mount = role.OutputKVMount
	}
	if mount == "" {
		return logical.ErrorResponse("未配置 KV 输出：mount 缺省且 role 未设置 output_kv_mount"), nil
	}
	if err := validateKVPathOverride(pathOverride); err != nil {
		return logical.ErrorResponse("%v", err), nil
	}

	policy := kvPolicyEnforce
	if force {
		policy = kvPolicyOverwrite
	}

	var updated *cacheEntry
	var writeErr error
	if err := b.cacheUpdate(ctx, req.Storage, key, func(e *cacheEntry) *cacheEntry {
		oldLinked, oldMount, oldOverride := e.OutputKVLinked, e.OutputKVMount, e.OutputKVPathOverride
		e.OutputKVLinked = true
		e.OutputKVMount = mount
		e.OutputKVPathOverride = pathOverride
		if _, werr := b.writeCertOutput(ctx, req, roleName, role, key, e, policy); werr != nil {
			// 回滚绑定字段：不得让失败的 link 改写"最后成功写入位置"。
			e.OutputKVLinked = oldLinked
			e.OutputKVMount = oldMount
			e.OutputKVPathOverride = oldOverride
			writeErr = werr
		}
		updated = e
		return e
	}); err != nil {
		return nil, err
	}
	if writeErr != nil {
		return kvWriteErrorResponse("KV link", writeErr), nil
	}
	return &logical.Response{Data: outputKVFields(updated, key)}, nil
}

// pathCertKVUnlink：解除绑定。delete_kv=true 时按条目实际绑定位置（生效 mount +
// override path）删除 KV 数据，删除失败返回错误；随后清空全部投影/link 字段。
func (b *backend) pathCertKVUnlink(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	cn := d.Get("cn").(string)
	deleteKV := d.Get("delete_kv").(bool)

	entry, key, err := b.findCertEntryByRoleCN(ctx, req.Storage, roleName, cn)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil // 404
	}

	kvDeleted := false
	if deleteKV {
		if mount := b.resolveOutputKVMount(ctx, req.Storage, entry); mount != "" {
			if derr := b.deleteCertOutput(ctx, req.ClientToken, mount, key, entry); derr != nil {
				return logical.ErrorResponse("删除 KV 数据失败: %v", derr), nil
			}
			kvDeleted = true
		}
	}

	if err := b.cacheUpdate(ctx, req.Storage, key, func(e *cacheEntry) *cacheEntry {
		e.OutputKVLinked = false
		e.OutputKVPathOverride = ""
		e.OutputKVMount = ""
		e.OutputKVPath = ""
		e.OutputKVStatus = ""
		return e
	}); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"unlinked": true, "kv_deleted": kvDeleted}}, nil
}
