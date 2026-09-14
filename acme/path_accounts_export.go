package acme

import (
	"context"
	"encoding/json"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/go-acme/lego/v5/acme"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathAccountsExport 构造账户导出（export）与导入（import）两个子路径。
// 导出是 read-only 的本地快照；导入是纯本地恢复 + 可选网络验证，绝不生成新密钥。
func pathAccountsExport(b *backend) []*framework.Path {
	export := &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name") + "/export",
		Fields:  map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathAccountExport},
		},
	}
	imp := &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name") + "/import",
		Fields: map[string]*framework.FieldSchema{
			"name":                    {Type: framework.TypeString},
			"server_url":              {Type: framework.TypeString, Required: true, Description: "ACME directory URL。"},
			"contact":                 {Type: framework.TypeString, Description: "联系邮箱。"},
			"terms_of_service_agreed": {Type: framework.TypeBool, Description: "是否同意 ToS；导入不是注册，不强制 true。"},
			"key_type":                {Type: framework.TypeString, Required: true, Description: "EC256/EC384/RSA2048/RSA4096/RSA8192。"},
			"private_key_pem":         {Type: framework.TypeString, Required: true, Description: "账户私钥 PKCS#8 PEM。"},
			"registration_json":       {Type: framework.TypeString, Required: true, Description: "lego ExtendedAccount JSON。"},
			"insecure_tls":            {Type: framework.TypeBool, Description: "跳过 CA 证书校验（仅 pebble 等自签测试环境）。"},
			"dns_providers":           {Type: framework.TypeSlice, Description: "[{name, zones?: [...]}]；引用须已存在。"},
			"overwrite":               {Type: framework.TypeBool, Description: "目标账户名已存在时整体覆盖。"},
			"verify":                  {Type: framework.TypeBool, Description: "导入前向 CA ResolveAccountByKey 验证并刷新注册信息。"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathAccountImport},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathAccountImport},
		},
	}
	return []*framework.Path{export, imp}
}

// pathAccountExport：导出账户身份最小充分集合（私钥 + 注册信息 + 所属 CA）。
func (b *backend) pathAccountExport(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	e, err := b.getAccount(ctx, req.Storage, d.Get("name").(string))
	if err != nil || e == nil {
		// 与 /key 路径一致：账户不存在时返回空响应（映射为 404）。
		return nil, err
	}
	// 键名与 api.AccountExport 的 mapstructure 标签严格对齐，保证可回灌 import。
	return &logical.Response{Data: map[string]interface{}{
		"kind":                    api.AccountExportKind,
		"version":                 api.AccountExportVersion,
		"name":                    e.Name,
		"server_url":              e.ServerURL,
		"contact":                 e.Contact,
		"terms_of_service_agreed": e.TOSAgreed,
		"key_type":                e.KeyType,
		"private_key_pem":         e.PrivateKeyPEM,
		"registration_json":       e.RegistrationJSON,
	}}, nil
}

// pathAccountImport：从导出载荷恢复账户；除 verify 外不与 CA 交互。
func (b *backend) pathAccountImport(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	serverURL := d.Get("server_url").(string)
	contact := d.Get("contact").(string)
	tosAgreed := d.Get("terms_of_service_agreed").(bool)
	keyType := d.Get("key_type").(string)
	privateKeyPEM := d.Get("private_key_pem").(string)
	registrationJSON := d.Get("registration_json").(string)
	insecureTLS := d.Get("insecure_tls").(bool)
	overwrite := d.Get("overwrite").(bool)
	verify := d.Get("verify").(bool)

	// 1. 必填校验：逐项指明缺失字段。
	if serverURL == "" {
		return logical.ErrorResponse("server_url 必填"), nil
	}
	if privateKeyPEM == "" {
		return logical.ErrorResponse("private_key_pem 必填"), nil
	}
	if registrationJSON == "" {
		return logical.ErrorResponse("registration_json 必填"), nil
	}
	if keyType == "" {
		return logical.ErrorResponse("key_type 必填"), nil
	}

	// 2. 格式与白名单校验（任一失败不落盘）。
	if _, valid := keyTypes[keyType]; !valid {
		return logical.ErrorResponse("key_type 必须是 EC256/EC384/RSA2048/RSA4096/RSA8192"), nil
	}
	if _, err := parsePrivateKeyPEM(privateKeyPEM); err != nil {
		return logical.ErrorResponse("private_key_pem 解析失败: %v", err), nil
	}
	var reg acme.ExtendedAccount
	if err := json.Unmarshal([]byte(registrationJSON), &reg); err != nil {
		return logical.ErrorResponse("registration_json 解析失败: %v", err), nil
	}

	entry := &accountEntry{
		Name:             name,
		ServerURL:        serverURL,
		Contact:          contact,
		TOSAgreed:        tosAgreed,
		KeyType:          keyType,
		PrivateKeyPEM:    privateKeyPEM,
		RegistrationJSON: registrationJSON,
		InsecureTLS:      insecureTLS,
	}
	// dns_providers 解析并校验引用存在（与主路径一致，fail-fast）。
	if refs, ok := d.GetOk("dns_providers"); ok {
		if err := decodeDNSProviderRefs(refs, &entry.DNSProviders); err != nil {
			return logical.ErrorResponse("dns_providers 解析失败: %v", err), nil
		}
	}
	for _, ref := range entry.DNSProviders {
		dp, err := b.getDNSProvider(ctx, req.Storage, ref.Name)
		if err != nil {
			return nil, err
		}
		if dp == nil {
			return logical.ErrorResponse("dns-provider %q 不存在", ref.Name), nil
		}
	}

	// 3. 冲突检查：目标名已存在且未显式覆盖 → 拒绝。
	existing, err := b.getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if existing != nil && !overwrite {
		return logical.ErrorResponse("account %q 已存在（用 overwrite=true 覆盖）", name), nil
	}

	// 4. 可选网络验证：确认私钥已在该 CA 注册，并用 CA 返回刷新 registration_json。
	verified := false
	if verify {
		// lego 依据 user 上是否已有 Registration 决定 NewAccount 请求用 KID 还是
		// JWK 签名；ResolveAccountByKey 走的是 new-account 端点，必须用 JWK。
		// 因此验证时用纯私钥（不带 registration）构造临时用户，否则携带的 KID
		// 会被 CA 以 "No JWK in JWS header" 拒绝。
		verifyEntry := *entry
		verifyEntry.RegistrationJSON = ""
		user, err := AccountLegoUser(&verifyEntry)
		if err != nil {
			return nil, err
		}
		client, err := newLegoClient(user, entry.ServerURL, entry.InsecureTLS)
		if err != nil {
			return nil, err
		}
		resolved, err := client.Registration.ResolveAccountByKey(ctx)
		if err != nil {
			// verify 失败：不落盘，保持目标存储原状。
			return logical.ErrorResponse("verify 失败（私钥未在该 CA 注册或网络失败）: %v", err), nil
		}
		regJSON, err := json.Marshal(resolved)
		if err != nil {
			return nil, err
		}
		entry.RegistrationJSON = string(regJSON)
		verified = true
	}

	// 5. 持久化（纯本地恢复：不生成新密钥、不调 Register）。
	if err := storage.PutAccount(ctx, req.Storage, name, entry); err != nil {
		return nil, err
	}

	// 6. 响应键与 api.AccountImportResult 对齐。
	return &logical.Response{Data: map[string]interface{}{
		"name":        name,
		"server_url":  serverURL,
		"contact":     contact,
		"key_type":    keyType,
		"verified":    verified,
		"overwritten": existing != nil,
	}}, nil
}
