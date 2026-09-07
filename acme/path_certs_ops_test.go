package acme

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathCertsExtended(t *testing.T) {
	b, s := testBackendConfig(t)
	ctx := context.Background()

	// 注册 role
	require.NoError(t, s.Put(ctx, &logical.StorageEntry{
		Key: "roles/testrole",
		Value: mustJSON(t, &roleEntry{
			Account:          "acc1",
			AllowedDomains:   []string{"example.com"},
			AllowBareDomains: true,
			AllowSubdomains:  true,
		}),
	}))

	// 注入一个缓存条目
	cKey := "cache-key-1"
	entry := &cacheEntry{
		Users:          1,
		Role:           "testrole",
		Account:        "acc1",
		CN:             "example.com",
		Domains:        []string{"example.com", "*.example.com"},
		CertificatePEM: selfSignedCertFor(t, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour)),
		PrivateKeyPEM:  "-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----",
	}
	require.NoError(t, b.cachePut(ctx, s, cKey, entry))

	// 1. LIST certs
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "certs",
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	certs, ok := resp.Data["certificates"].([]certSummary)
	require.True(t, ok)
	require.Len(t, certs, 1)
	assert.Equal(t, "example.com", certs[0].CommonName)
	assert.Equal(t, "testrole", certs[0].Role)

	// 2. LIST certs/testrole/list
	respRole, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "certs/testrole/list",
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, respRole)
	certsRole, ok := respRole.Data["certificates"].([]certSummary)
	require.True(t, ok)
	require.Len(t, certsRole, 1)

	// 3. GET certs/testrole/example.com
	respGet, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "certs/testrole/example.com",
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, respGet)
	assert.Equal(t, "example.com", respGet.Data["common_name"])
	assert.Equal(t, "testrole", respGet.Data["role"])
	assert.Contains(t, respGet.Data["certificate"], "CERTIFICATE")

	// 4. DELETE (Revoke) certs/testrole/example.com
	respDel, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "certs/testrole/example.com",
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, respDel)
	assert.Equal(t, true, respDel.Data["revoked"])

	// 验证已从缓存删除
	gotEntry, err := b.cacheGet(ctx, s, cKey)
	require.NoError(t, err)
	assert.Nil(t, gotEntry)
}
