package acme

import (
	"context"
	"strings"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathDNSProviderRename：纯本地 dns-provider 改名。provider 名不参与 cacheKey，
// 无需迁移缓存与 KV 输出；只需更新 account 的 DNSProviders 引用，最后迁移条目
// 本身（提交点）。
func (b *backend) pathDNSProviderRename(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	old := d.Get("name").(string)
	newName := d.Get("new_name").(string)

	if newName == "" {
		return logical.ErrorResponse("new_name 必填"), nil
	}
	if newName == old {
		return logical.ErrorResponse("新名与旧名相同"), nil
	}
	if strings.Contains(newName, "/") {
		return logical.ErrorResponse("new_name 不能包含 \"/\""), nil
	}
	entry, err := b.getDNSProvider(ctx, req.Storage, old)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("dns-provider %q 不存在", old), nil
	}
	existing, err := b.getDNSProvider(ctx, req.Storage, newName)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("dns-provider %q 已存在", newName), nil
	}

	// 级联：account.DNSProviders[].Name 逐项替换，保留列表顺序；无变更不写回。
	migratedAccounts := 0
	accountNames, err := storage.ListAccounts(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	for _, name := range accountNames {
		acc, err := storage.GetAccount(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		if acc == nil {
			continue
		}
		changed := false
		for i := range acc.DNSProviders {
			if acc.DNSProviders[i].Name == old {
				acc.DNSProviders[i].Name = newName
				changed = true
			}
		}
		if !changed {
			continue
		}
		if err := storage.PutAccount(ctx, req.Storage, name, acc); err != nil {
			return nil, err
		}
		migratedAccounts++
	}

	// 提交点（最后做）：先写新键再删旧键。
	if err := storage.PutDNSProvider(ctx, req.Storage, newName, entry); err != nil {
		return nil, err
	}
	if err := storage.DeleteDNSProvider(ctx, req.Storage, old); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"old_name":          old,
		"new_name":          newName,
		"migrated_accounts": migratedAccounts,
	}}, nil
}
