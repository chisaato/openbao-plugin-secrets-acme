package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// setupIssuable 预置：pebble、dns-provider/exec 记录（直写存储绕过 fail-fast
// 试读）、account（未引用任何 dns provider，供路由缺失断言）、role。
// 说明：v1 仅 DNS-01，单测环境无法真正落 TXT（fake provider 不产生记录），
// 真实端到端签发由 Task 14 验收测试（exec provider + challtestsrv）覆盖；
// 本文件聚焦校验逻辑与「失败路径不落缓存/不写 KV」。
func setupIssuable(t *testing.T) (*backend, logical.Storage, *pebbleEnv, string) {
	t.Helper()
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 注册 dns-provider 记录（本组用例不经过 buildRoutes，仅补全环境）
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key: "dns-providers/exec",
		Value: mustJSON(t, &dnsProviderEntry{
			Type:           "cloudflare",
			CredentialsRef: &credentialsRef{Mount: "secret", Path: "dns/cf"},
		}),
	}))

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	})
	require.NoError(t, err)
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":            "le",
			"allowed_domains":    "example.com",
			"allow_bare_domains": true,
			"allow_subdomains":   true,
		},
	})
	require.NoError(t, err)
	return b, storage, env, "exec"
}

func TestIssuePathValidation(t *testing.T) {
	b, storage, _, _ := setupIssuable(t)
	ctx := context.Background()

	// 域名不在白名单 → 报错
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage,
		Data:    map[string]interface{}{"common_name": "evil.com"},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "不在 allowed_domains 内")

	// 白名单内但 provider 路由缺失（account 无 dns_providers）→ 报错含"路由"
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage,
		Data:    map[string]interface{}{"common_name": "example.com"},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "路由")
}

func TestIssueWithFakeProvider(t *testing.T) {
	// 路由与凭据/provider 构造成功，但 TXT 无法真正落地（fake token 无法写
	// Cloudflare，pebble 侧校验失败）——聚焦「失败前」的路径：响应错误但
	// 缓存未生成、无 KV 写入。
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))
	ctx := context.Background()

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "dns-providers/cf",
		Storage: storage, ClientToken: "test-token",
		Data: map[string]interface{}{
			"type":            "cloudflare",
			"credentials_ref": map[string]interface{}{"mount": "s", "path": "p"},
		},
	})
	require.NoError(t, err)

	data := accountData(env.DirURL)
	data["dns_providers"] = []interface{}{map[string]interface{}{"name": "cf"}}
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, ClientToken: "test-token", Data: data,
	})
	require.NoError(t, err)

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage, ClientToken: "test-token",
		Data: map[string]interface{}{
			"account":            "le",
			"allowed_domains":    "example.com",
			"allow_bare_domains": true,
			"output_kv_mount":    "kv-certs",
		},
	})
	require.NoError(t, err)

	w := &recordingKVWriter{}
	b.kvWriter = w

	// 签发：路由与凭据/provider 构造成功，TXT 无法真正落地（pebble 侧校验失败）
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage, ClientToken: "test-token",
		Data: map[string]interface{}{"common_name": "example.com"},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError()) // pebble DNS 校验失败（预期）
	require.Empty(t, w.writes)      // 失败不写 KV
	n, _ := b.cacheCount(ctx, storage)
	require.Equal(t, 0, n) // 失败不落缓存
}
