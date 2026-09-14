package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// writeDNSProviderReq 构造一次 dns-provider 写请求；CliToken 非空以满足 fake loader。
func writeDNSProviderReq(t *testing.T, b *backend, s logical.Storage, name string, op logical.Operation, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   op,
		Path:        "dns-providers/" + name,
		Storage:     s,
		ClientToken: "test-token",
		Data:        data,
	})
	require.NoError(t, err)
	return resp
}

// getStoredProvider 读取已持久化的 dns-provider 条目。
func getStoredProvider(t *testing.T, b *backend, s logical.Storage, name string) *dnsProviderEntry {
	t.Helper()
	entry, err := b.getDNSProvider(context.Background(), s, name)
	require.NoError(t, err)
	require.NotNil(t, entry, "dns-provider %q 应已持久化", name)
	return entry
}

// 1. 纯标量创建：模拟 bao CLI 只发字符串（credentials_version 由框架 TypeInt 转换）。
func TestDNSProviderFlatScalars(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))

	resp := writeDNSProviderReq(t, b, s, "cf", logical.CreateOperation, map[string]interface{}{
		"type":                   "cloudflare",
		"credentials_mount":      "secret",
		"credentials_path":       "dns/cf",
		"credentials_kv_version": "2",
		"credentials_version":    "3",
	})
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	entry := getStoredProvider(t, b, s, "cf")
	require.NotNil(t, entry.CredentialsRef)
	require.Equal(t, "secret", entry.CredentialsRef.Mount)
	require.Equal(t, "dns/cf", entry.CredentialsRef.Path)
	require.Equal(t, "2", entry.CredentialsRef.KVVersion)
	require.Equal(t, 3, entry.CredentialsRef.Version)
}

// 2. credentials_ref 传 JSON 字符串（兼容旧格式）。
func TestDNSProviderCredentialsRefJSONString(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))

	resp := writeDNSProviderReq(t, b, s, "cf", logical.CreateOperation, map[string]interface{}{
		"type":            "cloudflare",
		"credentials_ref": `{"mount":"secret","path":"dns/cf","kv_version":"2"}`,
	})
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	entry := getStoredProvider(t, b, s, "cf")
	require.NotNil(t, entry.CredentialsRef)
	require.Equal(t, "secret", entry.CredentialsRef.Mount)
	require.Equal(t, "dns/cf", entry.CredentialsRef.Path)
	require.Equal(t, "2", entry.CredentialsRef.KVVersion)
}

// 3. credentials_ref 传原生 map 对象（模拟旧 bao-acme CLI 直接发对象）。
func TestDNSProviderCredentialsRefNativeMap(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))

	resp := writeDNSProviderReq(t, b, s, "cf", logical.CreateOperation, map[string]interface{}{
		"type":            "cloudflare",
		"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
	})
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	entry := getStoredProvider(t, b, s, "cf")
	require.NotNil(t, entry.CredentialsRef)
	require.Equal(t, "secret", entry.CredentialsRef.Mount)
	require.Equal(t, "dns/cf", entry.CredentialsRef.Path)
}

// 4. credentials_ref 传普通字符串：必须返回 400（ErrorResponse），绝不能 panic。
func TestDNSProviderCredentialsRefPlainString(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))

	resp := writeDNSProviderReq(t, b, s, "cf", logical.CreateOperation, map[string]interface{}{
		"type":            "cloudflare",
		"credentials_ref": "mount=secret,path=dns/cf",
	})
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "JSON")

	// 未写入任何条目。
	entry, err := b.getDNSProvider(context.Background(), s, "cf")
	require.NoError(t, err)
	require.Nil(t, entry)
}

// 5. 标量与 credentials_ref 同时给：标量逐项覆盖对应子字段，其余子字段保留。
func TestDNSProviderFlatScalarsOverrideCredentialsRef(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))

	resp := writeDNSProviderReq(t, b, s, "cf", logical.CreateOperation, map[string]interface{}{
		"type":              "cloudflare",
		"credentials_ref":   `{"mount":"old","path":"old/path","kv_version":"1"}`,
		"credentials_mount": "newmount",
		"credentials_path":  "new/path",
	})
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	entry := getStoredProvider(t, b, s, "cf")
	require.NotNil(t, entry.CredentialsRef)
	require.Equal(t, "newmount", entry.CredentialsRef.Mount)
	require.Equal(t, "new/path", entry.CredentialsRef.Path)
	// 未被标量覆盖的 kv_version 保留自 credentials_ref。
	require.Equal(t, "1", entry.CredentialsRef.KVVersion)
}

// 6. credentials_keys：非法 JSON → 400；合法 JSON → 正确落存储。
func TestDNSProviderCredentialsKeys(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"cf_token": "tok",
	}))

	// 非法 JSON：返回 400，不写库。
	resp := writeDNSProviderReq(t, b, s, "bad", logical.CreateOperation, map[string]interface{}{
		"type":              "cloudflare",
		"credentials_mount": "secret",
		"credentials_path":  "dns/cf",
		"credentials_keys":  "not-json",
	})
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "credentials_keys")

	bad, err := b.getDNSProvider(context.Background(), s, "bad")
	require.NoError(t, err)
	require.Nil(t, bad)

	// 合法 JSON：写入并按映射试读成功。
	resp = writeDNSProviderReq(t, b, s, "cf", logical.CreateOperation, map[string]interface{}{
		"type":              "cloudflare",
		"credentials_mount": "secret",
		"credentials_path":  "dns/cf",
		"credentials_keys":  `{"CLOUDFLARE_DNS_API_TOKEN":"cf_token"}`,
	})
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	entry := getStoredProvider(t, b, s, "cf")
	require.NotNil(t, entry.CredentialsRef)
	require.Equal(t, map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "cf_token"}, entry.CredentialsRef.Keys)
}

// 7. update 增量：本请求完全不含凭据字段时，存量凭据原样保留；
// 仅给部分标量时，其余子字段也保留（以存量为底合并）。
func TestDNSProviderFlatUpdateKeepsCredentials(t *testing.T) {
	b, s := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))

	resp := writeDNSProviderReq(t, b, s, "cf", logical.CreateOperation, map[string]interface{}{
		"type":              "cloudflare",
		"credentials_mount": "secret",
		"credentials_path":  "dns/cf",
		"credentials_keys":  `{"CLOUDFLARE_DNS_API_TOKEN":"cf_token"}`,
	})
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	// 仅改超时，不碰凭据。
	resp = writeDNSProviderReq(t, b, s, "cf", logical.UpdateOperation, map[string]interface{}{
		"propagation_timeout": 300,
	})
	require.False(t, resp != nil && resp.IsError(), "更新失败: %v", resp)

	entry := getStoredProvider(t, b, s, "cf")
	require.NotNil(t, entry.CredentialsRef)
	require.Equal(t, "secret", entry.CredentialsRef.Mount)
	require.Equal(t, "dns/cf", entry.CredentialsRef.Path)
	require.Equal(t, map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "cf_token"}, entry.CredentialsRef.Keys)

	// 仅覆盖 mount：path 与 keys 从存量合并保留。
	resp = writeDNSProviderReq(t, b, s, "cf", logical.UpdateOperation, map[string]interface{}{
		"credentials_mount": "secret2",
	})
	require.False(t, resp != nil && resp.IsError(), "更新失败: %v", resp)

	entry = getStoredProvider(t, b, s, "cf")
	require.Equal(t, "secret2", entry.CredentialsRef.Mount)
	require.Equal(t, "dns/cf", entry.CredentialsRef.Path)
	require.Equal(t, map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "cf_token"}, entry.CredentialsRef.Keys)
}
