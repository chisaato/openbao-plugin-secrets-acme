package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestCacheEndpoints(t *testing.T) {
	b, storage := testBackendConfig(t)
	ctx := context.Background()
	require.NoError(t, b.cachePut(ctx, storage, "k1", &cacheEntry{Users: 1}))
	require.NoError(t, b.cachePut(ctx, storage, "k2", &cacheEntry{Users: 1}))

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "cache", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, 2, resp.Data["cached_certs"])

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "cache", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, 2, resp.Data["cleared"])

	resp, _ = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "cache", Storage: storage,
	})
	require.Equal(t, 0, resp.Data["cached_certs"])
}
