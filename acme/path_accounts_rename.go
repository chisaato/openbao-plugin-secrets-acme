package acme

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathAccountRename：纯本地账户改名，不与 CA 交互。
// cacheKey 不含账户名（仅由 ServerURL/KeyType/账号私钥/域名决定），故改名后
// 缓存条目 key 与 KV 输出路径 certs/{certID} 均不变，无需搬家或迁移；这里
// 仅做展示字段级联：就地更新缓存条目的 Account 字段，再级联 roles/jobs 引用，
// 最后迁移账户条目本身（提交点）。
func (b *backend) pathAccountRename(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
	entry, err := b.getAccount(ctx, req.Storage, old)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("account %q 不存在", old), nil
	}
	existing, err := b.getAccount(ctx, req.Storage, newName)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("account %q 已存在", newName), nil
	}

	// 缓存条目：key 不变，仅就地更新 Account 展示字段。直写 req.Storage，
	// 不经 cachePut/cacheDelete——保持与既有写路径一致且避免额外锁协调。
	migratedCerts := 0
	keys, err := req.Storage.List(ctx, storageKeyCache)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		item, err := req.Storage.Get(ctx, storageKeyCache+k)
		if err != nil {
			return nil, err
		}
		if item == nil {
			continue
		}
		var ce cacheEntry
		if err := item.DecodeJSON(&ce); err != nil {
			return nil, err
		}
		// 仅更新归属旧账户名的条目。
		if ce.Account != old {
			continue
		}
		ce.Account = newName
		raw, err := json.Marshal(&ce)
		if err != nil {
			return nil, err
		}
		if err := req.Storage.Put(ctx, &logical.StorageEntry{Key: storageKeyCache + k, Value: raw}); err != nil {
			return nil, err
		}
		migratedCerts++
	}

	// 角色引用：把指向旧账户名的 role 改为新名。
	migratedRoles := 0
	roleNames, err := storage.ListRoles(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	for _, name := range roleNames {
		role, err := storage.GetRole(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		if role == nil || role.Account != old {
			continue
		}
		role.Account = newName
		if err := storage.PutRole(ctx, req.Storage, name, role); err != nil {
			return nil, err
		}
		migratedRoles++
	}

	// Job 引用：CacheKey 是提交时快照、驱动时按 account 现值重算，不改。
	migratedJobs := 0
	jobIDs, err := storage.ListJobs(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	for _, id := range jobIDs {
		job, err := storage.GetJob(ctx, req.Storage, id)
		if err != nil {
			return nil, err
		}
		if job == nil || job.Account != old {
			continue
		}
		job.Account = newName
		if err := storage.PutJob(ctx, req.Storage, id, job); err != nil {
			return nil, err
		}
		migratedJobs++
	}

	// 账户条目迁移（提交点，最后做）。
	entry.Name = newName
	if err := storage.PutAccount(ctx, req.Storage, newName, entry); err != nil {
		return nil, err
	}
	if err := storage.DeleteAccount(ctx, req.Storage, old); err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"old_name":       old,
		"new_name":       newName,
		"migrated_roles": migratedRoles,
		"migrated_jobs":  migratedJobs,
		"migrated_certs": migratedCerts,
	}
	return &logical.Response{Data: data}, nil
}
