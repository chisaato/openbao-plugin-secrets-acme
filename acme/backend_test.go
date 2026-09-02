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

// testBackend 构造并 Setup backend，注入 loader（nil=默认 apiCredentialLoader），
// 返回 (*backend, inmem Storage) 供路径测试复用。
// 注：sdk v2.6.2 的 TestBackendConfig 不再填充 StorageView（恒为 nil），
// brief 原写法返回 conf.StorageView 会得到 nil storage，故显式构造 InmemStorage。
func testBackend(t *testing.T, loader CredentialLoader) (*backend, logical.Storage) {
	t.Helper()
	conf := logical.TestBackendConfig()
	b, err := Backend(conf)
	require.NoError(t, err)
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatal(err)
	}
	if loader != nil {
		b.credLoader = loader
	}
	return b, &logical.InmemStorage{}
}
