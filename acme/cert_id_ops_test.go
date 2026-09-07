package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertForceIssueAndCertIDOperations(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	role := &roleEntry{
		Account:          "le",
		AllowedDomains:   []string{"example.com", "*.example.com"},
		AllowBareDomains: true,
		AllowSubdomains:  true,
		CacheForRatio:    70,
	}
	putRoleFixture(t, ctx, storage, role)
	putRoleFixtureAt(t, ctx, storage, "web", role)
	b.issueFn = stubIssueFn(t)

	// 1. 同步签发一张证书，落入缓存
	res1, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      "certs/web",
		Data: map[string]interface{}{
			"common_name": "example.com",
			"sync":        true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res1)
	reused1, _ := res1.Data["reused"].(bool)
	assert.False(t, reused1)

	// 2. 正常请求相同域名，命中缓存 (reused: true)
	res2, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      "certs/web",
		Data: map[string]interface{}{
			"common_name": "example.com",
			"sync":        true,
		},
	})
	require.NoError(t, err)
	require.True(t, res2.Data["reused"].(bool))

	// 3. 携带 force: true，跳过缓存，直接重新签发 (reused: false)
	resForce, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      "certs/web",
		Data: map[string]interface{}{
			"common_name": "example.com",
			"sync":        true,
			"force":       true,
		},
	})
	require.NoError(t, err)
	reusedForce, _ := resForce.Data["reused"].(bool)
	assert.False(t, reusedForce)

	// 4. 测试 LIST certs 输出 id 与 cert_id
	resList, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.ListOperation,
		Path:      "certs",
	})
	require.NoError(t, err)
	certs, ok := resList.Data["certificates"].([]certSummary)
	require.True(t, ok)
	require.NotEmpty(t, certs)
	certID := certs[0].ID
	assert.NotEmpty(t, certID)

	// 5. 测试 GET certs/id/{id} (完整 ID 与 12 位短 ID)
	resGetID, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "certs/id/" + certID,
	})
	require.NoError(t, err)
	require.NotNil(t, resGetID)
	assert.Equal(t, certID, resGetID.Data["id"])
	assert.Equal(t, "example.com", resGetID.Data["common_name"])

	// 测试短 ID 前缀检索 (12 位短 ID)
	shortID := certID[:12]
	resGetShort, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "certs/id/" + shortID,
	})
	require.NoError(t, err)
	require.NotNil(t, resGetShort)
	assert.Equal(t, certID, resGetShort.Data["id"])

	// 6. 测试 DELETE certs/id/{short_id}
	resDelID, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.DeleteOperation,
		Path:      "certs/id/" + shortID,
	})
	require.NoError(t, err)
	require.NotNil(t, resDelID)
	assert.True(t, resDelID.Data["revoked"].(bool))

	// 验证已删除
	resCheck, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "certs/id/" + shortID,
	})
	require.NoError(t, err)
	assert.Nil(t, resCheck)
}
