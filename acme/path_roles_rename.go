package acme

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathRoleRename：纯本地 role 改名。cacheKey 只由 role 内容与域名派生、不含
// role 名，故缓存键与 KV 输出路径不变，仅需更新引用字符串（job 与缓存条目的
// Role 字段），最后迁移 role 条目本身（提交点）。
func (b *backend) pathRoleRename(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
	entry, err := b.getRole(ctx, req.Storage, old)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("role %q 不存在", old), nil
	}
	existing, err := b.getRole(ctx, req.Storage, newName)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("role %q 已存在", newName), nil
	}

	// 缓存条目 Role 字段更新：键不变，持 cacheMu 直接覆写条目内容（勿调
	// cachePut/cacheUpdate，持锁调用会死锁）。
	migratedCerts := 0
	if err := func() error {
		b.cacheMu.Lock()
		defer b.cacheMu.Unlock()
		keys, err := req.Storage.List(ctx, storageKeyCache)
		if err != nil {
			return err
		}
		for _, k := range keys {
			item, err := req.Storage.Get(ctx, storageKeyCache+k)
			if err != nil {
				return err
			}
			if item == nil {
				continue
			}
			var ce cacheEntry
			if err := item.DecodeJSON(&ce); err != nil {
				return err
			}
			if ce.Role != old {
				continue
			}
			ce.Role = newName
			raw, err := json.Marshal(&ce)
			if err != nil {
				return err
			}
			// 键不变，原位覆写。
			if err := req.Storage.Put(ctx, &logical.StorageEntry{Key: storageKeyCache + k, Value: raw}); err != nil {
				return err
			}
			migratedCerts++
		}
		return nil
	}(); err != nil {
		return nil, err
	}

	// job 引用：JobEntry.Role 是驱动时 getRole 的键，不改则 job 驱动报 role 不存在。
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
		if job == nil || job.Role != old {
			continue
		}
		job.Role = newName
		if err := storage.PutJob(ctx, req.Storage, id, job); err != nil {
			return nil, err
		}
		migratedJobs++
	}

	// 提交点（最后做）：先写新键再删旧键。
	if err := storage.PutRole(ctx, req.Storage, newName, entry); err != nil {
		return nil, err
	}
	if err := storage.DeleteRole(ctx, req.Storage, old); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"old_name":       old,
		"new_name":       newName,
		"migrated_jobs":  migratedJobs,
		"migrated_certs": migratedCerts,
	}}, nil
}
