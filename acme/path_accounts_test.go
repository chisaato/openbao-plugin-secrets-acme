package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func accountData(dirURL string) map[string]interface{} {
	return map[string]interface{}{
		"server_url":              dirURL,
		"contact":                 "admin@example.com",
		"terms_of_service_agreed": true,
		"insecure_tls":            true,
	}
}

func TestAccountsLifecycle(t *testing.T) {
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 创建（Register 到 pebble）
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create: %v", resp)

	// 读取：不回显私钥
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, env.DirURL, resp.Data["server_url"])
	require.Equal(t, "EC256", resp.Data["key_type"])
	require.Nil(t, resp.Data["private_key"])

	// key_type 直接改 → 报错（引导 rollover）
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "accounts/le",
		Storage: storage, Data: map[string]interface{}{"key_type": "EC384"},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "rollover")

	// key 导出
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le/key", Storage: storage,
	})
	require.NoError(t, err)
	key1 := resp.Data["private_key"].(string)
	require.Contains(t, key1, "BEGIN PRIVATE KEY")

	// rollover EC256 → RSA2048
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le/rollover",
		Storage: storage, Data: map[string]interface{}{"key_type": "RSA2048"},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "rollover: %v", resp)
	resp, _ = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le/key", Storage: storage,
	})
	require.NotEqual(t, key1, resp.Data["private_key"])

	// 更新 contact（同 CA → UpdateRegistration）
	data := accountData(env.DirURL)
	data["contact"] = "new@example.com"
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "accounts/le",
		Storage: storage, Data: data,
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "update: %v", resp)
	resp, _ = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le", Storage: storage,
	})
	require.Equal(t, "new@example.com", resp.Data["contact"])

	// LIST
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "accounts/", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"le"}, resp.Data["keys"])

	// 删除（Deactivate 尽力而为 + 删存储）
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "accounts/le", Storage: storage,
	})
	require.NoError(t, err)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le", Storage: storage,
	})
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestAccountInvalidKeyType(t *testing.T) {
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	data := accountData(env.DirURL)
	data["key_type"] = "RSA1024"
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/bad",
		Storage: storage, Data: data,
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

// 部分更新（仅传未提及字段之外的字段）不得重置 bool 字段：
// insecure_tls 被静默重置 false 会让依赖自签 CA 的账户后续操作 TLS 失败。
func TestAccountPartialUpdatePreservesBools(t *testing.T) {
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 创建：insecure_tls=true / terms_of_service_agreed=true（pebble 自签场景）
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create: %v", resp)

	// 部分更新：仅改 contact，不传 insecure_tls/terms_of_service_agreed
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "accounts/le",
		Storage: storage, Data: map[string]interface{}{"contact": "part@example.com"},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "partial update: %v", resp)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, "part@example.com", resp.Data["contact"])
	// 未提及的 bool 字段保留旧值
	require.Equal(t, true, resp.Data["insecure_tls"])
	require.Equal(t, true, resp.Data["terms_of_service_agreed"])

	// 显式传 terms_of_service_agreed=true 允许覆盖（GetOk 对显式值返回 ok=true）。
	// insecure_tls=true 保留生效，同 CA UpdateRegistration 可达 pebble。
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "accounts/le",
		Storage: storage, Data: map[string]interface{}{"terms_of_service_agreed": true},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "tos update: %v", resp)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, true, resp.Data["terms_of_service_agreed"])
}
