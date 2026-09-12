package acme

import (
	"context"
	"testing"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// ---- 夹具：直写 storage，免 pebble/ACME 交互 ----

func putRawEntry(t *testing.T, ctx context.Context, s logical.Storage, key string, v interface{}) {
	t.Helper()
	require.NoError(t, s.Put(ctx, &logical.StorageEntry{Key: key, Value: mustJSON(t, v)}))
}

func putAccountRaw(t *testing.T, ctx context.Context, s logical.Storage, name string) *accountEntry {
	t.Helper()
	entry := &accountEntry{
		Name:             name,
		ServerURL:        "https://acme.test/dir",
		Contact:          "admin@example.com",
		KeyType:          "EC256",
		PrivateKeyPEM:    "KEY-" + name,
		RegistrationJSON: `{"uri":"reg-` + name + `"}`,
	}
	putRawEntry(t, ctx, s, storageKeyAccounts+name, entry)
	return entry
}

func putRoleRaw(t *testing.T, ctx context.Context, s logical.Storage, name string, role *roleEntry) {
	t.Helper()
	putRawEntry(t, ctx, s, storageKeyRoles+name, role)
}

func renameAccount(t *testing.T, b *backend, s logical.Storage, old, newName string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "accounts/" + old + "/rename",
		Storage:   s,
		Data:      map[string]interface{}{"new_name": newName},
	})
	require.NoError(t, err)
	return resp
}

func TestAccountRenameBasic(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	src := putAccountRaw(t, ctx, s, "old")
	resp := renameAccount(t, b, s, "old", "new")
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Equal(t, "old", resp.Data["old_name"])
	require.Equal(t, "new", resp.Data["new_name"])

	// 新账户条目各字段保留，Name 更新
	got, err := storage.GetAccount(ctx, s, "new")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "new", got.Name)
	require.Equal(t, src.ServerURL, got.ServerURL)
	require.Equal(t, src.Contact, got.Contact)
	require.Equal(t, src.PrivateKeyPEM, got.PrivateKeyPEM)
	require.Equal(t, src.RegistrationJSON, got.RegistrationJSON)

	// 旧账户消失
	gone, err := storage.GetAccount(ctx, s, "old")
	require.NoError(t, err)
	require.Nil(t, gone)

	// LIST 只剩新名
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "accounts/", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"new"}, resp.Data["keys"])
}

func TestAccountRenameUpdatesReferences(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putAccountRaw(t, ctx, s, "old")
	putRoleRaw(t, ctx, s, "r1", &roleEntry{Account: "old", AllowedDomains: []string{"example.com"}})
	putRoleRaw(t, ctx, s, "r2", &roleEntry{Account: "other", AllowedDomains: []string{"example.com"}})
	putRawEntry(t, ctx, s, storageKeyJobs+"j1", &jobEntry{ID: "j1", Role: "r1", Account: "old", Status: "completed"})
	putRawEntry(t, ctx, s, storageKeyJobs+"j2", &jobEntry{ID: "j2", Role: "r2", Account: "other", Status: "completed"})

	resp := renameAccount(t, b, s, "old", "new")
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Equal(t, 1, resp.Data["migrated_roles"])
	require.Equal(t, 1, resp.Data["migrated_jobs"])
	require.Equal(t, 0, resp.Data["migrated_certs"])

	r1, err := storage.GetRole(ctx, s, "r1")
	require.NoError(t, err)
	require.Equal(t, "new", r1.Account)
	r2, err := storage.GetRole(ctx, s, "r2")
	require.NoError(t, err)
	require.Equal(t, "other", r2.Account)

	j1, err := storage.GetJob(ctx, s, "j1")
	require.NoError(t, err)
	require.Equal(t, "new", j1.Account)
	j2, err := storage.GetJob(ctx, s, "j2")
	require.NoError(t, err)
	require.Equal(t, "other", j2.Account)
}

func TestAccountRenameMigratesCache(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putAccountRaw(t, ctx, s, "old")
	role := &roleEntry{Account: "old", AllowedDomains: []string{"a.com"}}
	putRoleRaw(t, ctx, s, "r", role)

	domains := []string{"a.com"}
	oldKey := cacheKey(role, domains)
	require.NoError(t, s.Put(ctx, &logical.StorageEntry{
		Key: storageKeyCache + oldKey,
		Value: mustJSON(t, &cacheEntry{
			Users: 3, Account: "old", Role: "r", CN: "a.com", Domains: domains,
		}),
	}))

	resp := renameAccount(t, b, s, "old", "new")
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Equal(t, 1, resp.Data["migrated_certs"])

	newRole := *role
	newRole.Account = "new"
	newKey := cacheKey(&newRole, domains)
	require.NotEqual(t, oldKey, newKey)

	migrated, err := storage.GetCache(ctx, s, newKey)
	require.NoError(t, err)
	require.NotNil(t, migrated)
	require.Equal(t, 3, migrated.Users)
	require.Equal(t, "new", migrated.Account)
	require.Equal(t, "r", migrated.Role)

	old, err := storage.GetCache(ctx, s, oldKey)
	require.NoError(t, err)
	require.Nil(t, old, "旧缓存键应被删除")
}

func TestAccountRenameCacheOrphanEntry(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putAccountRaw(t, ctx, s, "old")
	const orphanKey = "orphan-cache-key"
	require.NoError(t, s.Put(ctx, &logical.StorageEntry{
		Key: storageKeyCache + orphanKey,
		Value: mustJSON(t, &cacheEntry{
			Users: 1, Account: "old", Role: "gone", CN: "x.com", Domains: []string{"x.com"},
		}),
	}))

	resp := renameAccount(t, b, s, "old", "new")
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Equal(t, 1, resp.Data["migrated_certs"])

	// role 不存在 → 键保持不变，仅更新 Account 字段
	got, err := storage.GetCache(ctx, s, orphanKey)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "new", got.Account)
}

func TestAccountRenameConflicts(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putAccountRaw(t, ctx, s, "old")
	putAccountRaw(t, ctx, s, "taken")

	// new_name 缺失
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "accounts/old/rename",
		Storage: s, Data: map[string]interface{}{},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())

	// 新名与旧名相同
	resp = renameAccount(t, b, s, "old", "old")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "相同")

	// 新名已存在
	resp = renameAccount(t, b, s, "old", "taken")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "已存在")

	// 新名含 "/"
	resp = renameAccount(t, b, s, "old", "a/b")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "/")

	// 旧账户不存在
	resp = renameAccount(t, b, s, "nope", "fresh")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "不存在")
}

func TestAccountRenameKVMigration(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putAccountRaw(t, ctx, s, "old")
	role := &roleEntry{Account: "old", AllowedDomains: []string{"a.com"}, OutputKVMount: "kv"}
	putRoleRaw(t, ctx, s, "r", role)

	domains := []string{"a.com"}
	oldKey := cacheKey(role, domains)
	require.NoError(t, s.Put(ctx, &logical.StorageEntry{
		Key: storageKeyCache + oldKey,
		Value: mustJSON(t, &cacheEntry{
			Users: 1, Account: "old", Role: "r", CN: "a.com", Domains: domains,
			CertificatePEM: "C", PrivateKeyPEM: "K", IssuerCertificatePEM: "I",
		}),
	}))

	w := &recordingKVWriter{}
	b.kvWriter = w

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "accounts/old/rename",
		Storage:     s,
		ClientToken: "test-token",
		Data:        map[string]interface{}{"new_name": "new"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Nil(t, resp.Data["warnings"])

	newRole := *role
	newRole.Account = "new"
	newKey := cacheKey(&newRole, domains)

	require.Len(t, w.writes, 1)
	require.Equal(t, "certs/"+newKey, w.writes[0].path)
	require.Equal(t, "kv", w.writes[0].mount)
	require.Len(t, w.deletes, 1)
	require.Equal(t, "certs/"+oldKey, w.deletes[0].path)
	require.Equal(t, "kv", w.deletes[0].mount)
}
