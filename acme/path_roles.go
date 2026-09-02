package acme

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyRoles = "roles/"

// roleEntry：签发策略（域名白名单、缓存策略、KV 输出目标）。
type roleEntry struct {
	Account          string   `json:"account"`
	AllowedDomains   []string `json:"allowed_domains"`
	AllowBareDomains bool     `json:"allow_bare_domains"`
	AllowSubdomains  bool     `json:"allow_subdomains"`
	DisableCache     bool     `json:"disable_cache"`
	CacheForRatio    int      `json:"cache_for_ratio"`
	OutputKVMount    string   `json:"output_kv_mount"`
}

// validateNames：通配符剥 "*." 后按 bare/sub 语义校验（含 PKI 语义一致性）。
// "*.allowed 域" 视为对白名单域的通配引用直接放行；其余与裸域/子域规则一致。
func validateNames(cn string, alt []string, role *roleEntry) error {
	for _, name := range append([]string{cn}, alt...) {
		if name == "" {
			return fmt.Errorf("域名为空")
		}
		wildcard := strings.HasPrefix(name, "*.")
		bare := strings.TrimPrefix(name, "*.")
		matched := false
		for _, allowed := range role.AllowedDomains {
			if bare == allowed {
				if wildcard {
					// 通配符按 bare 计：*.example.com 覆盖 example.com 白名单域。
					matched = true
					break
				}
				if !role.AllowBareDomains {
					return fmt.Errorf("域名 %q 是裸域，需要 allow_bare_domains", name)
				}
				matched = true
				break
			}
			if strings.HasSuffix(bare, "."+allowed) {
				if !role.AllowSubdomains {
					return fmt.Errorf("域名 %q 是子域，需要 allow_subdomains", name)
				}
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("域名 %q 不在 allowed_domains 内", name)
		}
	}
	return nil
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	item, err := s.Get(ctx, storageKeyRoles+name)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	var role roleEntry
	if err := item.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func pathRoles(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name":               {Type: framework.TypeString, Description: "role 名（certs/{role} 引用）。"},
		"account":            {Type: framework.TypeString, Required: true, Description: "accounts/{name}。"},
		"allowed_domains":    {Type: framework.TypeCommaStringSlice, Required: true, Description: "允许的域名（逗号分隔）。"},
		"allow_bare_domains": {Type: framework.TypeBool, Description: "允许裸域。"},
		"allow_subdomains":   {Type: framework.TypeBool, Description: "允许子域。"},
		"disable_cache":      {Type: framework.TypeBool, Description: "禁用证书缓存（每次真签发）。"},
		"cache_for_ratio":    {Type: framework.TypeInt, Default: 70, Description: "剩余寿命低于总寿命该百分比时重签；(0,100]。"},
		"output_kv_mount":    {Type: framework.TypeString, Description: "证书同步输出到该 KV mount（certs/{role}/{cn}）；空=不输出。"},
	}
	entry := &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields:  fields,
		ExistenceCheck: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
			r, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
			return r != nil, err
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					role, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
					if err != nil || role == nil {
						return nil, err
					}
					return &logical.Response{Data: map[string]interface{}{
						"account":            role.Account,
						"allowed_domains":    role.AllowedDomains,
						"allow_bare_domains": role.AllowBareDomains,
						"allow_subdomains":   role.AllowSubdomains,
						"disable_cache":      role.DisableCache,
						"cache_for_ratio":    role.CacheForRatio,
						"output_kv_mount":    role.OutputKVMount,
					}}, nil
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					return nil, req.Storage.Delete(ctx, storageKeyRoles+d.Get("name").(string))
				},
			},
		},
	}
	list := &framework.Path{
		Pattern: "roles/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					keys, err := req.Storage.List(ctx, storageKeyRoles)
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

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	existing, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	role := &roleEntry{CacheForRatio: 70}
	if existing != nil {
		role = existing
	}

	acc, ok := d.GetOk("account")
	if !ok {
		if existing == nil {
			return logical.ErrorResponse("account 必填"), nil
		}
	} else {
		role.Account = acc.(string)
	}
	account, err := b.getAccount(ctx, req.Storage, role.Account)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return logical.ErrorResponse("account %q 不存在", role.Account), nil
	}

	if ad, ok := d.GetOk("allowed_domains"); ok {
		role.AllowedDomains = ad.([]string)
	}
	if existing == nil && len(role.AllowedDomains) == 0 {
		return logical.ErrorResponse("allowed_domains 必填"), nil
	}
	// bool 字段仅在请求中显式出现时覆盖（GetOk 对显式 false 也返回 ok=true，
	// 允许显式改回 false）；未提及则保留旧值，避免部分更新静默重置。
	// 与 path_accounts.go 的 account bool 字段处理一致。
	if v, ok := d.GetOk("allow_bare_domains"); ok {
		role.AllowBareDomains = v.(bool)
	}
	if v, ok := d.GetOk("allow_subdomains"); ok {
		role.AllowSubdomains = v.(bool)
	}
	if v, ok := d.GetOk("disable_cache"); ok {
		role.DisableCache = v.(bool)
	}
	// cache_for_ratio 有 Default=70：未显式携带键时 GetOk ok=false，跳过以保留
	// 旧值；显式携带时校验 (0,100]（Default 70 非零，显式传值恒可读到）。
	if ratio, ok := d.GetOk("cache_for_ratio"); ok {
		v := ratio.(int)
		if v <= 0 || v > 100 {
			return logical.ErrorResponse("cache_for_ratio 必须在 (0,100] 内"), nil
		}
		role.CacheForRatio = v
	}
	if o, ok := d.GetOk("output_kv_mount"); ok {
		role.OutputKVMount = o.(string)
	}

	item, err := logical.StorageEntryJSON(storageKeyRoles+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, item); err != nil {
		return nil, err
	}
	return nil, nil
}
