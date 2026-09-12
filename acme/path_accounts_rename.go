package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathAccountRename：纯本地账户改名，不与 CA 交互。
// 采用缓存迁移模式：逐条把旧账户名下的缓存条目按新 role.Account 重算 cacheKey
// 并搬家（先写新键再删旧键，崩溃安全），再级联更新 roles/jobs 引用，最后迁移
// 账户条目本身（提交点）；KV 输出迁移为尽力而为，失败仅告警不阻断。
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

	// 待迁移的 KV 输出项（cacheKey 与输出路径一致，键变化时资格随之变化）。
	type kvMigration struct {
		oldKey   string
		newKey   string
		entry    *cacheEntry
		roleName string
	}
	var pending []kvMigration
	migratedCerts := 0

	// 缓存键迁移：role.Account 参与 cacheKey 计算，改名后键随之变化。全程持
	// cacheMu，并直接用 req.Storage 读写——cachePut/cacheDelete 内部同样加锁，
	// 持锁调用会死锁。
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
			// 仅迁移归属旧账户名的条目。
			if ce.Account != old {
				continue
			}
			newKey := k
			var role *roleEntry
			if ce.Role != "" {
				// getRole 不加 cacheMu，持锁调用安全。
				role, err = b.getRole(ctx, req.Storage, ce.Role)
				if err != nil {
					return err
				}
				if role != nil {
					roleCopy := *role
					roleCopy.Account = newName
					newKey = cacheKey(&roleCopy, ce.Domains)
				}
			}
			ce.Account = newName
			raw, err := json.Marshal(&ce)
			if err != nil {
				return err
			}
			// 先写新键再删旧键，中途失败也不会丢条目。
			if err := req.Storage.Put(ctx, &logical.StorageEntry{Key: storageKeyCache + newKey, Value: raw}); err != nil {
				return err
			}
			if newKey != k {
				if err := req.Storage.Delete(ctx, storageKeyCache+k); err != nil {
					return err
				}
			}
			if role != nil && role.OutputKVMount != "" && newKey != k {
				copied := ce
				pending = append(pending, kvMigration{oldKey: k, newKey: newKey, entry: &copied, roleName: ce.Role})
			}
			migratedCerts++
		}
		return nil
	}(); err != nil {
		return nil, err
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

	// Job 引用：CacheKey 是提交时快照、驱动时按 role 现值重算，不改。
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

	// KV 输出迁移：尽力而为，失败仅告警不阻断。
	var warnings []string
	for _, m := range pending {
		// 重新取 role 现值（上一步已把 Account 更新为新名）。
		role, err := storage.GetRole(ctx, req.Storage, m.roleName)
		if err != nil || role == nil {
			warnings = append(warnings, fmt.Sprintf("KV 输出迁移跳过 %s -> %s: role %q 不存在", m.oldKey, m.newKey, m.roleName))
			continue
		}
		if _, err := b.writeCertOutput(ctx, req, m.roleName, role, m.newKey, m.entry, kvPolicyEnforce); err != nil {
			warnings = append(warnings, fmt.Sprintf("KV 输出迁移失败 %s -> %s: %v", m.oldKey, m.newKey, err))
			continue
		}
		if err := b.deleteCertOutput(ctx, req.ClientToken, role.OutputKVMount, m.oldKey); err != nil {
			warnings = append(warnings, fmt.Sprintf("KV 旧输出删除失败 %s -> %s: %v", m.oldKey, m.newKey, err))
		}
	}

	data := map[string]interface{}{
		"old_name":       old,
		"new_name":       newName,
		"migrated_roles": migratedRoles,
		"migrated_jobs":  migratedJobs,
		"migrated_certs": migratedCerts,
	}
	if len(warnings) > 0 {
		data["warnings"] = warnings
	}
	return &logical.Response{Data: data}, nil
}
