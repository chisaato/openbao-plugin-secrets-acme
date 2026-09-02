package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestFactory(t *testing.T) {
	conf := logical.TestBackendConfig()
	b, err := Factory(context.Background(), conf)
	require.NoError(t, err)
	require.NotNil(t, b)

	fb, ok := b.(*backend)
	require.True(t, ok, "Factory 应返回 *backend")
	require.Equal(t, Version, fb.RunningVersion)
	require.NotEmpty(t, fb.RunningVersion)
}
