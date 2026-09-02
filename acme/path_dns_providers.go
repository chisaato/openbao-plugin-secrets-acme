package acme

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyDNSProviders = "dns-providers/"

// dnsProviderEntry 是 dns-providers/{name} 的持久化记录。
// 凭据只存引用（credentials_ref），签发时实时读取（不快照）。
type dnsProviderEntry struct {
	Type               string          `json:"type"`
	CredentialsRef     *credentialsRef `json:"credentials_ref,omitempty"`
	PropagationTimeout time.Duration   `json:"propagation_timeout"`
	PollingInterval    time.Duration   `json:"polling_interval"`
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
	if _, err := newProvider(ctx, entry.Type, providerOpts{
		PropagationTimeout: entry.PropagationTimeout,
		PollingInterval:    entry.PollingInterval,
	}, resolveKeys(raw, *entry.CredentialsRef, envNames[entry.Type])); err != nil {
		return fmt.Errorf("provider 试构造失败: %w", err)
	}
	return nil
}

// getDNSProvider 读取单个条目；不存在时返回 (nil, nil)。
func (b *backend) getDNSProvider(ctx context.Context, s logical.Storage, name string) (*dnsProviderEntry, error) {
	item, err := s.Get(ctx, storageKeyDNSProviders+name)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	var entry dnsProviderEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func pathDNSProviders(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "DNS provider 名称（account 中以该名称引用）。",
		},
		"type": {
			Type:        framework.TypeString,
			Description: "lego provider 类型，白名单：cloudflare、alidns、tencentcloud。创建后不可改。",
		},
		"credentials_ref": {
			Type:        framework.TypeMap,
			Description: "凭据引用 {mount, path, kv_version=\"2\", version=0, keys={LEGO_VAR: 用户键名}}。写操作时试读校验但不快照。",
		},
		"propagation_timeout": {
			Type:        framework.TypeDurationSecond,
			Description: "DNS 传播等待上限（秒）；0=用 provider 默认。",
		},
		"polling_interval": {
			Type:        framework.TypeDurationSecond,
			Description: "传播轮询间隔（秒）；0=用 provider 默认。",
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
						"type":                entry.Type,
						"propagation_timeout": int64(entry.PropagationTimeout.Seconds()),
						"polling_interval":    int64(entry.PollingInterval.Seconds()),
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
	return []*framework.Path{write, list}
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

	if refRaw, ok := d.GetOk("credentials_ref"); ok {
		ref := &credentialsRef{}
		if err := mapstructure.WeakDecode(refRaw, ref); err != nil {
			return logical.ErrorResponse("credentials_ref 解析失败: %v", err), nil
		}
		entry.CredentialsRef = ref
	}
	if v, ok := d.GetOk("propagation_timeout"); ok {
		entry.PropagationTimeout = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("polling_interval"); ok {
		entry.PollingInterval = time.Duration(v.(int)) * time.Second
	}

	if _, ok := registry[entry.Type]; !ok {
		names := make([]string, 0, len(registry))
		for n := range registry {
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
