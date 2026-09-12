package acme

import (
	"context"
	"testing"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func renameRole(t *testing.T, b *backend, s logical.Storage, old, newName string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + old + "/rename",
		Storage:   s,
		Data:      map[string]interface{}{"new_name": newName},
	})
	require.NoError(t, err)
	return resp
}

func TestRoleRenameBasic(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"}, AllowBareDomains: true}
	putRoleRaw(t, ctx, s, "old", role)

	resp := renameRole(t, b, s, "old", "new")
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Equal(t, "old", resp.Data["old_name"])
	require.Equal(t, "new", resp.Data["new_name"])

	got, err := storage.GetRole(ctx, s, "new")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, role.Account, got.Account)
	require.Equal(t, role.AllowedDomains, got.AllowedDomains)
	require.Equal(t, role.AllowBareDomains, got.AllowBareDomains)

	gone, err := storage.GetRole(ctx, s, "old")
	require.NoError(t, err)
	require.Nil(t, gone)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "roles/", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"new"}, resp.Data["keys"])
}

func TestRoleRenameUpdatesReferences(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putRoleRaw(t, ctx, s, "old", &roleEntry{Account: "le", AllowedDomains: []string{"example.com"}})
	putRawEntry(t, ctx, s, storageKeyJobs+"j1", &jobEntry{ID: "j1", Role: "old", Account: "le", Status: "completed"})
	putRawEntry(t, ctx, s, storageKeyJobs+"j2", &jobEntry{ID: "j2", Role: "other", Account: "le", Status: "completed"})
	// 缓存条目键不变，仅 Role 字段更新。
	putRawEntry(t, ctx, s, storageKeyCache+"k1", &cacheEntry{
		Users: 1, Account: "le", Role: "old", CN: "a.com", Domains: []string{"a.com"},
	})
	putRawEntry(t, ctx, s, storageKeyCache+"k2", &cacheEntry{
		Users: 1, Account: "le", Role: "other", CN: "b.com", Domains: []string{"b.com"},
	})

	resp := renameRole(t, b, s, "old", "new")
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Equal(t, 1, resp.Data["migrated_jobs"])
	require.Equal(t, 1, resp.Data["migrated_certs"])

	j1, err := storage.GetJob(ctx, s, "j1")
	require.NoError(t, err)
	require.Equal(t, "new", j1.Role)
	j2, err := storage.GetJob(ctx, s, "j2")
	require.NoError(t, err)
	require.Equal(t, "other", j2.Role)

	// k1 仍在原键，Role 已更新；k2 不变。
	c1, err := storage.GetCache(ctx, s, "k1")
	require.NoError(t, err)
	require.NotNil(t, c1)
	require.Equal(t, "new", c1.Role)
	c2, err := storage.GetCache(ctx, s, "k2")
	require.NoError(t, err)
	require.Equal(t, "other", c2.Role)
}

func TestRoleRenameConflicts(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putRoleRaw(t, ctx, s, "old", &roleEntry{Account: "le"})
	putRoleRaw(t, ctx, s, "taken", &roleEntry{Account: "le"})

	// new_name 缺失
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/old/rename",
		Storage: s, Data: map[string]interface{}{},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())

	resp = renameRole(t, b, s, "old", "old")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "相同")

	resp = renameRole(t, b, s, "old", "taken")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "已存在")

	resp = renameRole(t, b, s, "nope", "fresh")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "不存在")
}
