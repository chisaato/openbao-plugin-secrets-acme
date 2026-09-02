package acme

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-acme/lego/v5/registration"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyAccounts = "accounts/"

func (b *backend) getAccount(ctx context.Context, s logical.Storage, name string) (*accountEntry, error) {
	item, err := s.Get(ctx, storageKeyAccounts+name)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	var entry accountEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func pathAccounts(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name":                    {Type: framework.TypeString, Description: "账户名。"},
		"server_url":              {Type: framework.TypeString, Description: "ACME directory URL（如 LE 生产/staging 或 pebble）。可改：同 key 在新 CA 重新注册。"},
		"contact":                 {Type: framework.TypeString, Description: "联系邮箱。"},
		"terms_of_service_agreed": {Type: framework.TypeBool, Description: "是否同意 ToS。"},
		"key_type":                {Type: framework.TypeString, Default: "EC256", Description: "EC256/EC384/RSA2048/RSA4096/RSA8192；创建后不可改（换钥用 rollover）。"},
		"insecure_tls":            {Type: framework.TypeBool, Description: "跳过 CA 证书校验（仅 pebble 等自签测试环境）。"},
		"dns_providers":           {Type: framework.TypeSlice, Description: "[{name, zones?: [...]}]；zones 空=兜底路由。"},
	}

	entry := &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name"),
		Fields:  fields,
		ExistenceCheck: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
			e, err := b.getAccount(ctx, req.Storage, d.Get("name").(string))
			return e != nil, err
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathAccountWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathAccountWrite},
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					e, err := b.getAccount(ctx, req.Storage, d.Get("name").(string))
					if err != nil || e == nil {
						return nil, err
					}
					// 主端点不回显私钥；导出走 accounts/{name}/key。
					return &logical.Response{Data: map[string]interface{}{
						"name":                    e.Name,
						"server_url":              e.ServerURL,
						"contact":                 e.Contact,
						"terms_of_service_agreed": e.TOSAgreed,
						"key_type":                e.KeyType,
						"insecure_tls":            e.InsecureTLS,
						"dns_providers":           e.DNSProviders,
					}}, nil
				},
			},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathAccountDelete},
		},
	}
	list := &framework.Path{
		Pattern: "accounts/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					keys, err := req.Storage.List(ctx, storageKeyAccounts)
					if err != nil {
						return nil, err
					}
					return logical.ListResponse(keys), nil
				},
			},
		},
	}
	rollover := &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name") + "/rollover",
		Fields: map[string]*framework.FieldSchema{
			"name":     {Type: framework.TypeString},
			"key_type": {Type: framework.TypeString, Required: true, Description: "新密钥类型（白名单内）。"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathAccountRollover},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathAccountRollover},
		},
	}
	keyExport := &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name") + "/key",
		Fields:  map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					e, err := b.getAccount(ctx, req.Storage, d.Get("name").(string))
					if err != nil || e == nil {
						return nil, err
					}
					// 私钥导出：建议对该路径配置严格 ACL（见文档）。
					return &logical.Response{Data: map[string]interface{}{"private_key": e.PrivateKeyPEM}}, nil
				},
			},
		},
	}
	return []*framework.Path{entry, list, rollover, keyExport}
}

func (b *backend) pathAccountWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	existing, err := b.getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	entry := &accountEntry{Name: name}
	if existing != nil {
		entry = existing
	}

	if serverURL, ok := d.GetOk("server_url"); ok {
		entry.ServerURL = serverURL.(string)
	} else if existing == nil {
		return logical.ErrorResponse("server_url 必填"), nil
	}
	if contact, ok := d.GetOk("contact"); ok {
		entry.Contact = contact.(string)
	} else if existing == nil {
		return logical.ErrorResponse("contact 必填"), nil
	}
	// bool 字段仅在请求中显式出现时覆盖（GetOk 对显式 false 也返回 ok=true，
	// 允许显式改回 false）；未提及则保留旧值，避免部分更新静默重置。
	if v, ok := d.GetOk("terms_of_service_agreed"); ok {
		entry.TOSAgreed = v.(bool)
	}
	// spec §4.2：创建（注册）必须显式同意 ToS，否则 ACME Register 语义不成立；
	// 更新路径不强制（注册时已同意，与 ACME 语义一致）。（M-1）
	if existing == nil && !entry.TOSAgreed {
		return logical.ErrorResponse("terms_of_service_agreed 必须为 true"), nil
	}
	if v, ok := d.GetOk("insecure_tls"); ok {
		entry.InsecureTLS = v.(bool)
	}
	if refs, ok := d.GetOk("dns_providers"); ok {
		if err := decodeDNSProviderRefs(refs, &entry.DNSProviders); err != nil {
			return logical.ErrorResponse("dns_providers 解析失败: %v", err), nil
		}
	}
	// 校验引用的 dns-provider 存在（fail-fast）。
	for _, ref := range entry.DNSProviders {
		dp, err := b.getDNSProvider(ctx, req.Storage, ref.Name)
		if err != nil {
			return nil, err
		}
		if dp == nil {
			return logical.ErrorResponse("dns-provider %q 不存在", ref.Name), nil
		}
	}

	// key_type：创建时生成密钥；更新时禁止直接改（走 rollover）。
	if existing == nil {
		kt, ok := d.GetOk("key_type")
		if !ok {
			kt = "EC256"
		}
		typed := kt.(string)
		if _, valid := keyTypes[typed]; !valid {
			return logical.ErrorResponse("key_type 必须是 EC256/EC384/RSA2048/RSA4096/RSA8192"), nil
		}
		entry.KeyType = typed
		_, pemStr, err := generatePrivateKeyPEM(keyTypes[typed])
		if err != nil {
			return nil, err
		}
		entry.PrivateKeyPEM = pemStr
	} else if kt, ok := d.GetOk("key_type"); ok && kt.(string) != entry.KeyType {
		return logical.ErrorResponse("key_type 创建后不可改，请使用 accounts/%s/rollover", name), nil
	}

	user, err := entry.legoUser()
	if err != nil {
		return nil, err
	}
	client, err := newLegoClient(user, entry.ServerURL, entry.InsecureTLS)
	if err != nil {
		return nil, err
	}

	switch {
	case existing == nil || existing.RegistrationJSON == "":
		// 新账户（或注册信息缺失）：向 CA 注册。
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{
			TermsOfServiceAgreed: entry.TOSAgreed,
		})
		if err != nil {
			return logical.ErrorResponse("ACME 注册失败: %v", err), nil
		}
		user.Registration = reg
	case existing.ServerURL != entry.ServerURL:
		// 同 key 换 CA：幂等回退注册（key 已在该 CA 注册则恢复，否则新建）。
		reg, err := client.Registration.ResolveAccountByKey(ctx)
		if err != nil {
			reg, err = client.Registration.Register(ctx, registration.RegisterOptions{
				TermsOfServiceAgreed: entry.TOSAgreed,
			})
			if err != nil {
				return logical.ErrorResponse("新 CA 注册失败: %v", err), nil
			}
		}
		user.Registration = reg
	default:
		// 同 CA 更新（contact/ToS）。
		reg, err := client.Registration.UpdateRegistration(ctx, registration.RegisterOptions{
			TermsOfServiceAgreed: entry.TOSAgreed,
		})
		if err != nil {
			return logical.ErrorResponse("ACME 更新失败: %v", err), nil
		}
		user.Registration = reg
	}

	regJSON, err := json.Marshal(user.Registration)
	if err != nil {
		return nil, err
	}
	entry.RegistrationJSON = string(regJSON)

	item, err := logical.StorageEntryJSON(storageKeyAccounts+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, item); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathAccountDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := b.getAccount(ctx, req.Storage, name)
	if err != nil || entry == nil {
		return nil, err
	}
	// 尽力注销 ACME 账户（lego 的 DeleteRegistration 即 Deactivate）；失败不阻断本地删除。
	if user, uerr := entry.legoUser(); uerr == nil {
		if client, cerr := newLegoClient(user, entry.ServerURL, entry.InsecureTLS); cerr == nil {
			_ = client.Registration.DeleteRegistration(ctx)
		}
	}
	return nil, req.Storage.Delete(ctx, storageKeyAccounts+name)
}

func (b *backend) pathAccountRollover(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := b.getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	kt := d.Get("key_type").(string)
	if _, valid := keyTypes[kt]; !valid {
		return logical.ErrorResponse("key_type 必须是 EC256/EC384/RSA2048/RSA4096/RSA8192"), nil
	}
	newKey, pemStr, err := generatePrivateKeyPEM(keyTypes[kt])
	if err != nil {
		return nil, err
	}
	user, err := entry.legoUser()
	if err != nil {
		return nil, err
	}
	client, err := newLegoClient(user, entry.ServerURL, entry.InsecureTLS)
	if err != nil {
		return nil, err
	}
	if err := client.Registration.KeyRollover(ctx, newKey); err != nil {
		return logical.ErrorResponse("key rollover 失败: %v", err), nil
	}
	entry.KeyType, entry.PrivateKeyPEM = kt, pemStr
	item, err := logical.StorageEntryJSON(storageKeyAccounts+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, item); err != nil {
		return nil, err
	}
	return nil, nil
}

// decodeDNSProviderRefs：TypeSlice 的 []interface{} → []dnsProviderRef。
func decodeDNSProviderRefs(raw interface{}, out *[]dnsProviderRef) error {
	list, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("期望数组，得到 %T", raw)
	}
	refs := make([]dnsProviderRef, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("dns_providers[%d]: 期望对象", i)
		}
		ref := dnsProviderRef{}
		if n, ok := m["name"].(string); ok {
			ref.Name = n
		}
		if ref.Name == "" {
			return fmt.Errorf("dns_providers[%d]: name 必填", i)
		}
		if zones, ok := m["zones"].([]interface{}); ok {
			for _, z := range zones {
				if zs, ok := z.(string); ok {
					ref.Zones = append(ref.Zones, zs)
				}
			}
		}
		refs = append(refs, ref)
	}
	*out = refs
	return nil
}
