package storage

import (
	"context"
	"testing"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestStorageCRUD(t *testing.T) {
	ctx := context.Background()
	s := &logical.InmemStorage{}

	// 1. Account
	acc := &AccountEntry{
		Name:      "test-acc",
		ServerURL: "https://acme.example.com",
		Contact:   "admin@example.com",
	}
	require.NoError(t, PutAccount(ctx, s, acc.Name, acc))
	gotAcc, err := GetAccount(ctx, s, acc.Name)
	require.NoError(t, err)
	require.Equal(t, acc.Contact, gotAcc.Contact)

	accs, err := ListAccounts(ctx, s)
	require.NoError(t, err)
	require.Contains(t, accs, acc.Name)

	require.NoError(t, DeleteAccount(ctx, s, acc.Name))
	deletedAcc, err := GetAccount(ctx, s, acc.Name)
	require.NoError(t, err)
	require.Nil(t, deletedAcc)

	// 2. Role
	role := &RoleEntry{
		Account:        "test-acc",
		AllowedDomains: []string{"example.com"},
	}
	require.NoError(t, PutRole(ctx, s, "web", role))
	gotRole, err := GetRole(ctx, s, "web")
	require.NoError(t, err)
	require.Equal(t, role.Account, gotRole.Account)

	roles, err := ListRoles(ctx, s)
	require.NoError(t, err)
	require.Contains(t, roles, "web")

	require.NoError(t, DeleteRole(ctx, s, "web"))

	// 3. DNSProvider
	dp := &DNSProviderEntry{
		Type:               "cloudflare",
		PropagationTimeout: 10 * time.Second,
	}
	require.NoError(t, PutDNSProvider(ctx, s, "cf", dp))
	gotDP, err := GetDNSProvider(ctx, s, "cf")
	require.NoError(t, err)
	require.Equal(t, dp.Type, gotDP.Type)

	dps, err := ListDNSProviders(ctx, s)
	require.NoError(t, err)
	require.Contains(t, dps, "cf")

	require.NoError(t, DeleteDNSProvider(ctx, s, "cf"))

	// 4. Job
	job := &JobEntry{
		ID:     "job-1",
		Role:   "web",
		Status: api.JobPending,
	}
	require.NoError(t, PutJob(ctx, s, job.ID, job))
	gotJob, err := GetJob(ctx, s, job.ID)
	require.NoError(t, err)
	require.Equal(t, job.Status, gotJob.Status)

	jobs, err := ListJobs(ctx, s)
	require.NoError(t, err)
	require.Contains(t, jobs, job.ID)

	require.NoError(t, DeleteJob(ctx, s, job.ID))

	// 5. Cache
	cache := &CacheEntry{
		Account: "test-acc",
		CN:      "example.com",
	}
	require.NoError(t, PutCache(ctx, s, "cache-1", cache))
	gotCache, err := GetCache(ctx, s, "cache-1")
	require.NoError(t, err)
	require.Equal(t, cache.CN, gotCache.CN)

	caches, err := ListCache(ctx, s)
	require.NoError(t, err)
	require.Contains(t, caches, "cache-1")

	require.NoError(t, DeleteCache(ctx, s, "cache-1"))
}
