package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueAltNamesAliasSupport(t *testing.T) {
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

	// 使用 alt_names 传入附加域名
	resps, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      "certs/web",
		Data: map[string]interface{}{
			"common_name": "example.com",
			"alt_names":   []string{"*.example.com"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resps)
	jobID, ok := resps.Data["job_id"].(string)
	require.True(t, ok)

	job := waitForJob(t, b, storage, jobID)
	require.NotNil(t, job)
	assert.Equal(t, "example.com", job.CN)
	assert.Equal(t, []string{"*.example.com"}, job.AltNames)
	assert.Equal(t, []string{"example.com", "*.example.com"}, job.Domains)
}
