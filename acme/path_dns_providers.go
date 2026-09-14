package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/dns"
	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/go-viper/mapstructure/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyDNSProviders = storage.StorageKeyDNSProviders

// dnsProviderEntry 兼容 storage.DNSProviderEntry
type dnsProviderEntry = storage.DNSProviderEntry

// handleLegacyCredentialsRef 兼容旧客户端的嵌套 credentials_ref：新 schema 将
// 其声明为 TypeString，而框架在回调前会对请求字段做类型校验，遇到 map 会直接
// 返回 "Field validation failed"（400），旧对象形态因此不可达。这里在进入框架
// 前把非字符串的 credentials_ref 归一化为 JSON 字符串，使其仍能走通；仅作用于
// dns-providers 路径，且不改动其余请求。
func handleLegacyCredentialsRef(req *logical.Request) {
	if req == nil || req.Data == nil {
		return
	}
	if !strings.HasPrefix(req.Path, "dns-providers/") {
		return
	}
	raw, ok := req.Data["credentials_ref"]
	if !ok || raw == nil {
		return
	}
	if _, isString := raw.(string); isString {
		return
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		// 保持原值，让回调的 default 分支返回 400（而非 panic）。
		return
	}
	req.Data["credentials_ref"] = string(encoded)
}

// HandleRequest 在框架处理前做一次凭据引用兼容归一化（见 handleLegacyCredentialsRef）。
func (b *backend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	handleLegacyCredentialsRef(req)
	return b.Backend.HandleRequest(ctx, req)
}

// HandleExistenceCheck 同 HandleRequest：存在性检查同样会先做字段类型校验，
// 故需在委派前归一化，避免旧客户端被 ACL 存在性检查拦下。
func (b *backend) HandleExistenceCheck(ctx context.Context, req *logical.Request) (bool, bool, error) {
	handleLegacyCredentialsRef(req)
	return b.Backend.HandleExistenceCheck(ctx, req)
}

// validateProviderEntry fail-fast 试读凭据并试构造 provider；
// 凭据仅在请求生命周期内使用，不落存储、不进日志、不进响应。
func (b *backend) validateProviderEntry(ctx context.Context, req *logical.Request, entry *dnsProviderEntry) error {
	if entry.CredentialsRef == nil {
		return fmt.Errorf("credentials_ref 必填")
	}
	raw, err := b.credLoader.Load(ctx, req.ClientToken, *entry.CredentialsRef)
	if err != nil {
		return fmt.Errorf("凭据试读失败: %w", err)
	}
	// 试构造即校验：引用可达、键名映射命中、超时参数可被 provider 接受。
	if _, err := dns.NewProvider(ctx, entry.Type, dns.ProviderOpts{
		PropagationTimeout: entry.PropagationTimeout,
		PollingInterval:    entry.PollingInterval,
	}, resolveKeys(raw, *entry.CredentialsRef, dns.EnvNames[entry.Type])); err != nil {
		return fmt.Errorf("provider 试构造失败: %w", err)
	}
	return nil
}

// getDNSProvider 读取单个条目；不存在时返回 (nil, nil)。
func (b *backend) getDNSProvider(ctx context.Context, s logical.Storage, name string) (*dnsProviderEntry, error) {
	return storage.GetDNSProvider(ctx, s, name)
}

func pathDNSProviders(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "DNS provider 名称（account 中以该名称引用）。",
		},
		"type": {
			Type:        framework.TypeString,
			Description: "lego provider 类型，白名单：cloudflare、alidns、tencentcloud、exec。创建后不可改。",
		},
		"credentials_mount": {
			Type:        framework.TypeString,
			Description: "凭据所在的 KV mount（如 secret）。",
		},
		"credentials_path": {
			Type:        framework.TypeString,
			Description: "凭据在 KV mount 内的路径（如 dns/cloudflare）。",
		},
		"credentials_kv_version": {
			Type:        framework.TypeString,
			Description: "KV 引擎版本 \"1\" 或 \"2\"；留空沿用默认(2)。",
		},
		"credentials_version": {
			Type:        framework.TypeInt,
			Description: "读取 KV 指定版本的数据；0=最新。",
		},
		"credentials_keys": {
			Type:        framework.TypeString,
			Description: "JSON 对象字符串，键名映射 {lego 变量名: 用户 KV 键名}，如 '{\"CLOUDFLARE_DNS_API_TOKEN\":\"cf_token\"}'。",
		},
		"credentials_ref": {
			Type:        framework.TypeString,
			Description: "（兼容）旧格式凭据引用，接受 JSON 对象或 JSON 字符串 {mount,path,kv_version,version,keys}；被上述标量字段逐项覆盖。",
		},
		"propagation_timeout": {
			Type:        framework.TypeDurationSecond,
			Description: "DNS 传播等待上限（秒）；0=用 provider 默认。",
		},
		"polling_interval": {
			Type:        framework.TypeDurationSecond,
			Description: "传播轮询间隔（秒）；0=用 provider 默认。",
		},
		"skip_propagation_check": {
			Type:        framework.TypeBool,
			Description: "跳过 lego 主动 DNS 传播预检，Present 后改为固定等待（私有 DNS/本地测试 CA 场景）。",
		},
		"propagation_wait": {
			Type:        framework.TypeDurationSecond,
			Description: "skip_propagation_check=true 时的固定等待秒数；0=立即通知 ACME。",
		},
		"resolvers": {
			Type:        framework.TypeCommaStringSlice,
			Description: "自定义递归 DNS 服务器列表（如 223.5.5.5:53,1.1.1.1:53），覆盖本地默认 DNS 避免污染或脏缓存。",
		},
	}

	write := &framework.Path{
		Pattern: "dns-providers/" + framework.GenericNameRegex("name"),
		Fields:  fields,
		ExistenceCheck: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
			entry, err := b.getDNSProvider(ctx, req.Storage, d.Get("name").(string))
			return entry != nil, err
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathDNSProviderWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathDNSProviderWrite},
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					entry, err := b.getDNSProvider(ctx, req.Storage, d.Get("name").(string))
					if err != nil || entry == nil {
						return nil, err
					}
					// 凭据引用不出现在响应中；计时字段以秒输出（与输入语义一致）。
					return &logical.Response{Data: map[string]interface{}{
						"type":                   entry.Type,
						"propagation_timeout":    int64(entry.PropagationTimeout.Seconds()),
						"polling_interval":       int64(entry.PollingInterval.Seconds()),
						"skip_propagation_check": entry.SkipPropagationCheck,
						"propagation_wait":       int64(entry.PropagationWait),
						"resolvers":              entry.Resolvers,
					}}, nil
				},
			},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathDNSProviderDelete},
		},
	}

	list := &framework.Path{
		Pattern: "dns-providers/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathDNSProviderList},
		},
	}
	rename := &framework.Path{
		Pattern: "dns-providers/" + framework.GenericNameRegex("name") + "/rename",
		Fields: map[string]*framework.FieldSchema{
			"name":     {Type: framework.TypeString},
			"new_name": {Type: framework.TypeString, Required: true, Description: "新 DNS provider 名。"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathDNSProviderRename},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathDNSProviderRename},
		},
	}
	return []*framework.Path{write, list, rename}
}

func (b *backend) pathDNSProviderWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	existing, err := b.getDNSProvider(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	entry := &dnsProviderEntry{}
	if existing != nil {
		// Update：以存量条目为底做字段级覆盖，type 不可改。
		entry = existing
	}

	if newType, ok := d.GetOk("type"); ok {
		typeName := newType.(string)
		if existing != nil && typeName != existing.Type {
			return logical.ErrorResponse("type 创建后不可改（当前 %q）", existing.Type), nil
		}
		entry.Type = typeName
	} else if existing == nil {
		return logical.ErrorResponse("type 必填"), nil
	}

	// 凭据引用：先以存量值为底，再依次应用 credentials_ref（兼容旧客户端）与扁平
	// 标量字段，实现字段级增量覆盖。credentials_ref 直接读 d.Raw 绕过 schema 类型
	// 转换，任何解析失败都返回 400，绝不 panic/500。
	ref := credentialsRef{}
	if existing != nil && existing.CredentialsRef != nil {
		ref = *existing.CredentialsRef
	}
	refTouched := false
	if raw, ok := d.Raw["credentials_ref"]; ok && raw != nil {
		switch v := raw.(type) {
		case map[string]interface{}:
			// 旧 bao-acme CLI 直接发嵌套对象；框架尚未转换。
			if err := mapstructure.WeakDecode(v, &ref); err != nil {
				return logical.ErrorResponse("credentials_ref 解析失败: %v", err), nil
			}
			refTouched = true
		case string:
			if err := json.Unmarshal([]byte(v), &ref); err != nil {
				return logical.ErrorResponse("credentials_ref 需为 JSON 对象/字符串，或改用 credentials_mount/credentials_path 标量字段"), nil
			}
			refTouched = true
		default:
			return logical.ErrorResponse("credentials_ref 需为 JSON 对象/字符串，或改用 credentials_mount/credentials_path 标量字段"), nil
		}
	}
	// 扁平标量逐项覆盖（仅显式出现时覆盖，保持增量更新语义）。
	if v, ok := d.GetOk("credentials_mount"); ok {
		ref.Mount = v.(string)
		refTouched = true
	}
	if v, ok := d.GetOk("credentials_path"); ok {
		ref.Path = v.(string)
		refTouched = true
	}
	if v, ok := d.GetOk("credentials_kv_version"); ok {
		ref.KVVersion = v.(string)
		refTouched = true
	}
	if v, ok := d.GetOk("credentials_version"); ok {
		ref.Version = v.(int)
		refTouched = true
	}
	if v, ok := d.GetOk("credentials_keys"); ok {
		var keys map[string]string
		if err := json.Unmarshal([]byte(v.(string)), &keys); err != nil {
			return logical.ErrorResponse("credentials_keys 需为 JSON 对象字符串: %v", err), nil
		}
		ref.Keys = keys
		refTouched = true
	}
	if refTouched {
		entry.CredentialsRef = &ref
	}
	if v, ok := d.GetOk("propagation_timeout"); ok {
		entry.PropagationTimeout = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("polling_interval"); ok {
		entry.PollingInterval = time.Duration(v.(int)) * time.Second
	}
	// bool 字段仅在请求中显式出现时覆盖（与 account/role 的显式 false 语义一致）。
	if v, ok := d.GetOk("skip_propagation_check"); ok {
		entry.SkipPropagationCheck = v.(bool)
	}
	if v, ok := d.GetOk("propagation_wait"); ok {
		if w := v.(int); w < 0 {
			return logical.ErrorResponse("propagation_wait 不能为负"), nil
		} else {
			entry.PropagationWait = w
		}
	}
	if v, ok := d.GetOk("resolvers"); ok {
		entry.Resolvers = v.([]string)
	}

	if _, ok := dns.Registry[entry.Type]; !ok {
		names := make([]string, 0, len(dns.Registry))
		for n := range dns.Registry {
			names = append(names, n)
		}
		sort.Strings(names)
		return logical.ErrorResponse("未知 dns provider 类型 %q（可用：%s）", entry.Type, strings.Join(names, ", ")), nil
	}

	// fail-fast 试读：保证引用正确、凭据可达，但不快照。
	if err := b.validateProviderEntry(ctx, req, entry); err != nil {
		return logical.ErrorResponse("%v", err), nil
	}

	item, err := logical.StorageEntryJSON(storageKeyDNSProviders+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, item); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathDNSProviderDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if _, err := b.getDNSProvider(ctx, req.Storage, name); err != nil {
		return nil, err
	}
	// 引用检查：任何 account 的 dns_providers 引用该名称则拒绝删除。
	keys, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		item, err := req.Storage.Get(ctx, "accounts/"+k)
		if err != nil {
			return nil, err
		}
		if item == nil {
			continue
		}
		var acc accountEntry
		if err := item.DecodeJSON(&acc); err != nil {
			return nil, err
		}
		for _, ref := range acc.DNSProviders {
			if ref.Name == name {
				return logical.ErrorResponse("dns-provider %q 正被 account %q 引用，无法删除", name, acc.Name), nil
			}
		}
	}
	return nil, req.Storage.Delete(ctx, storageKeyDNSProviders+name)
}

func (b *backend) pathDNSProviderList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, storageKeyDNSProviders)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}
