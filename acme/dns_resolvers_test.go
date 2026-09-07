package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSProviderResolversAndIssueOverrides(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))
	ctx := context.Background()

	// 1. 测试 dns-providers 配置写入 resolvers 与读取
	reqProv := &logical.Request{
		Storage: storage,
		Data: map[string]interface{}{
			"type":                   "cloudflare",
			"credentials_ref":        map[string]interface{}{"mount": "secret", "path": "cf"},
			"skip_propagation_check": true,
			"propagation_wait":       10,
			"resolvers":              []string{"223.5.5.5:53", "1.1.1.1:53"},
		},
	}
	resW, err := b.HandleRequest(ctx, &logical.Request{
		Storage:     storage,
		Operation:   logical.CreateOperation,
		Path:        "dns-providers/cf",
		ClientToken: "test-token",
		Data:        reqProv.Data,
	})
	require.NoError(t, err)
	require.False(t, resW != nil && resW.IsError(), "创建 dns-provider 失败: %v", resW)

	respProv, err := b.HandleRequest(ctx, &logical.Request{
		Storage:     storage,
		Operation:   logical.ReadOperation,
		Path:        "dns-providers/cf",
		ClientToken: "test-token",
	})
	require.NoError(t, err)
	require.NotNil(t, respProv)
	assert.Equal(t, []string{"223.5.5.5:53", "1.1.1.1:53"}, respProv.Data["resolvers"])
	assert.Equal(t, true, respProv.Data["skip_propagation_check"])
	assert.Equal(t, int64(10), respProv.Data["propagation_wait"])

	// 2. 准备 role 和 stub issueFn
	role := &roleEntry{
		Account:          "le",
		AllowedDomains:   []string{"example.com"},
		AllowBareDomains: true,
		AllowSubdomains:  true,
		CacheForRatio:    70,
	}
	putRoleFixture(t, ctx, storage, role)
	putRoleFixtureAt(t, ctx, storage, "role-cf", role)
	b.issueFn = stubIssueFn(t)

	// 3. 发起异步签发带 overrides
	skipVal := false
	waitVal := 30
	resps, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      "certs/role-cf",
		Data: map[string]interface{}{
			"common_name":            "example.com",
			"skip_propagation_check": skipVal,
			"propagation_wait":       waitVal,
			"resolvers":              []string{"8.8.8.8:53"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resps)
	jobID, ok := resps.Data["job_id"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, jobID)

	// 等待并检查存储中 job 的 overrides 字段
	job := waitForJob(t, b, storage, jobID)
	require.NotNil(t, job)
	require.NotNil(t, job.SkipPropagationCheck)
	assert.False(t, *job.SkipPropagationCheck)
	require.NotNil(t, job.PropagationWait)
	assert.Equal(t, 30, *job.PropagationWait)
	assert.Equal(t, []string{"8.8.8.8:53"}, job.Resolvers)
}
