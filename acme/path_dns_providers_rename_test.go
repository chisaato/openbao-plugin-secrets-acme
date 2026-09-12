package acme

import (
	"context"
	"testing"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func putDNSProviderRaw(t *testing.T, ctx context.Context, s logical.Storage, name string, entry *dnsProviderEntry) {
	t.Helper()
	putRawEntry(t, ctx, s, storageKeyDNSProviders+name, entry)
}

func renameDNSProvider(t *testing.T, b *backend, s logical.Storage, old, newName string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "dns-providers/" + old + "/rename",
		Storage:   s,
		Data:      map[string]interface{}{"new_name": newName},
	})
	require.NoError(t, err)
	return resp
}

func TestDNSProviderRenameBasic(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	entry := &dnsProviderEntry{
		Type:           "cloudflare",
		CredentialsRef: &credentialsRef{Mount: "secret", Path: "dns/cf"},
		Resolvers:      []string{"1.1.1.1:53"},
	}
	putDNSProviderRaw(t, ctx, s, "old", entry)

	resp := renameDNSProvider(t, b, s, "old", "new")
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Equal(t, "old", resp.Data["old_name"])
	require.Equal(t, "new", resp.Data["new_name"])
	require.Equal(t, 0, resp.Data["migrated_accounts"])

	got, err := storage.GetDNSProvider(ctx, s, "new")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "cloudflare", got.Type)
	require.Equal(t, []string{"1.1.1.1:53"}, got.Resolvers)

	gone, err := storage.GetDNSProvider(ctx, s, "old")
	require.NoError(t, err)
	require.Nil(t, gone)
}

func TestDNSProviderRenameUpdatesAccounts(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putDNSProviderRaw(t, ctx, s, "old", &dnsProviderEntry{Type: "cloudflare"})
	putAccountRaw(t, ctx, s, "a1")
	putAccountRaw(t, ctx, s, "a2")

	a1, err := storage.GetAccount(ctx, s, "a1")
	require.NoError(t, err)
	a1.DNSProviders = []dnsProviderRef{{Name: "old"}}
	require.NoError(t, storage.PutAccount(ctx, s, "a1", a1))

	// a2 混合引用：两条 old 都应改，且顺序保留。
	a2, err := storage.GetAccount(ctx, s, "a2")
	require.NoError(t, err)
	a2.DNSProviders = []dnsProviderRef{{Name: "other"}, {Name: "old"}, {Name: "old"}}
	require.NoError(t, storage.PutAccount(ctx, s, "a2", a2))

	resp := renameDNSProvider(t, b, s, "old", "new")
	require.False(t, resp.IsError(), "rename: %v", resp)
	require.Equal(t, 2, resp.Data["migrated_accounts"])

	got1, err := storage.GetAccount(ctx, s, "a1")
	require.NoError(t, err)
	require.Equal(t, []dnsProviderRef{{Name: "new"}}, got1.DNSProviders)

	got2, err := storage.GetAccount(ctx, s, "a2")
	require.NoError(t, err)
	require.Equal(t, []dnsProviderRef{{Name: "other"}, {Name: "new"}, {Name: "new"}}, got2.DNSProviders)
}

func TestDNSProviderRenameConflicts(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	putDNSProviderRaw(t, ctx, s, "old", &dnsProviderEntry{Type: "cloudflare"})
	putDNSProviderRaw(t, ctx, s, "taken", &dnsProviderEntry{Type: "cloudflare"})

	// new_name 缺失
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "dns-providers/old/rename",
		Storage: s, Data: map[string]interface{}{},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())

	resp = renameDNSProvider(t, b, s, "old", "old")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "相同")

	resp = renameDNSProvider(t, b, s, "old", "taken")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "已存在")

	resp = renameDNSProvider(t, b, s, "nope", "fresh")
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "不存在")
}
