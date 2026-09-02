package acme

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestDNSProviderCRUD(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))

	// 创建（fail-fast 试读通过）
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        "dns-providers/cf",
		Storage:     storage,
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":            "cloudflare",
			"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	// 读取
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "dns-providers/cf", Storage: storage, ClientToken: "test-token",
	})
	require.NoError(t, err)
	require.Equal(t, "cloudflare", resp.Data["type"])
	// 响应中计时字段为 int64 秒（与 TypeDurationSecond 输入语义一致）。
	require.Equal(t, int64(0), resp.Data["propagation_timeout"])
	require.Equal(t, int64(0), resp.Data["polling_interval"])

	// 未知类型 → 报错（含可用列表，registry 排序输出）
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        "dns-providers/bad",
		Storage:     storage,
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":            "dnspod",
			"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "alidns, cloudflare, exec, tencentcloud")

	// type 创建后不可改
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "dns-providers/cf",
		Storage:     storage,
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":            "alidns",
			"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "不可")

	// LIST
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation, Path: "dns-providers/", Storage: storage, ClientToken: "test-token",
	})
	require.NoError(t, err)
	require.Equal(t, []string{"cf"}, resp.Data["keys"])

	// 删除
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation, Path: "dns-providers/cf", Storage: storage, ClientToken: "test-token",
	})
	require.NoError(t, err)
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "dns-providers/cf", Storage: storage, ClientToken: "test-token",
	})
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestDNSProviderDeleteReferenced(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))
	// 预置 dns-provider 与引用它的 account
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        "dns-providers/cf",
		Storage:     storage,
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":            "cloudflare",
			"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
		},
	})
	require.NoError(t, err)
	acc := accountEntry{Name: "le", DNSProviders: []dnsProviderRef{{Name: "cf"}}}
	require.NoError(t, storage.Put(context.Background(), &logical.StorageEntry{
		Key:   "accounts/le",
		Value: mustJSON(t, acc),
	}))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation, Path: "dns-providers/cf", Storage: storage, ClientToken: "test-token",
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "le")
}

func TestDNSProviderTimeouts(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        "dns-providers/cf",
		Storage:     storage,
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":                "cloudflare",
			"credentials_ref":     map[string]interface{}{"mount": "secret", "path": "dns/cf"},
			"propagation_timeout": 300,
			"polling_interval":    5,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	// 响应：int64 秒。
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "dns-providers/cf", Storage: storage, ClientToken: "test-token",
	})
	require.NoError(t, err)
	require.Equal(t, int64(300), resp.Data["propagation_timeout"])
	require.Equal(t, int64(5), resp.Data["polling_interval"])

	// 存储：time.Duration。
	item, err := storage.Get(context.Background(), "dns-providers/cf")
	require.NoError(t, err)
	var entry dnsProviderEntry
	require.NoError(t, item.DecodeJSON(&entry))
	require.Equal(t, 300*time.Second, entry.PropagationTimeout)
	require.Equal(t, 5*time.Second, entry.PollingInterval)
}

func TestDNSProviderPropagationSkip(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        "dns-providers/cf",
		Storage:     storage,
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":                   "cloudflare",
			"credentials_ref":        map[string]interface{}{"mount": "secret", "path": "dns/cf"},
			"skip_propagation_check": true,
			"propagation_wait":       3,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	// 负值拒绝：framework 层对 TypeDurationSecond 直接校验负数。
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        "dns-providers/neg",
		Storage:     storage,
		ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":                   "cloudflare",
			"credentials_ref":        map[string]interface{}{"mount": "secret", "path": "dns/cf"},
			"skip_propagation_check": true,
			"propagation_wait":       -1,
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "negative")

	// 响应与存储回读
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "dns-providers/cf", Storage: storage, ClientToken: "test-token",
	})
	require.NoError(t, err)
	require.Equal(t, true, resp.Data["skip_propagation_check"])
	require.Equal(t, int64(3), resp.Data["propagation_wait"])

	item, err := storage.Get(context.Background(), "dns-providers/cf")
	require.NoError(t, err)
	var entry dnsProviderEntry
	require.NoError(t, item.DecodeJSON(&entry))
	require.True(t, entry.SkipPropagationCheck)
	require.Equal(t, 3, entry.PropagationWait)

	// 存量条目（无新键的旧 JSON）解码后为零值 = lego 默认预检，向后兼容。
	item, err = storage.Get(context.Background(), "dns-providers/neg")
	require.NoError(t, err)
	if item != nil {
		var old dnsProviderEntry
		require.NoError(t, item.DecodeJSON(&old))
		require.False(t, old.SkipPropagationCheck)
		require.Equal(t, 0, old.PropagationWait)
	}
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
