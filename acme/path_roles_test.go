package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestValidateNames(t *testing.T) {
	role := &roleEntry{AllowedDomains: []string{"example.com"}, AllowBareDomains: true, AllowSubdomains: true}
	require.NoError(t, validateNames("example.com", nil, role))
	require.NoError(t, validateNames("www.example.com", []string{"a.example.com"}, role))
	require.NoError(t, validateNames("*.example.com", nil, role))

	strict := &roleEntry{AllowedDomains: []string{"example.com"}}
	require.Error(t, validateNames("example.com", nil, strict))     // bare 未开
	require.Error(t, validateNames("www.example.com", nil, strict)) // sub 未开
	require.NoError(t, validateNames("*.example.com", nil, strict)) // 通配符按 bare 计

	wrong := &roleEntry{AllowedDomains: []string{"other.com"}, AllowBareDomains: true, AllowSubdomains: true}
	require.Error(t, validateNames("example.com", nil, wrong))

	anyName := &roleEntry{AllowAnyName: true}
	require.NoError(t, validateNames("example.com", []string{"foo.bar.org", "*.anywhere.io"}, anyName))
	require.Error(t, validateNames("", nil, anyName)) // 空域名仍应被拦截
}

func TestRoleCRUD(t *testing.T) {
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 预置 account
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	})
	require.NoError(t, err)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":          "le",
			"allowed_domains":  "example.com,example.org",
			"allow_subdomains": true,
			"output_kv_mount":  "kv-certs",
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create: %v", resp)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, "le", resp.Data["account"])
	require.Equal(t, 70, resp.Data["cache_for_ratio"]) // 默认
	require.Equal(t, "kv-certs", resp.Data["output_kv_mount"])

	// 不存在的 account → 报错。
	// 注：需携带 allowed_domains 穿过框架 Required 校验，才能命中 handler 内
	// 的 account 存在性检查（否则被框架提前拦截，测不到目标分支）。
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/bad",
		Storage: storage,
		Data: map[string]interface{}{
			"account":         "ghost",
			"allowed_domains": "example.com",
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "ghost")

	// ratio 越界 → 报错（同理补齐 Required 字段，命中 handler 内范围校验）。
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":         "le",
			"allowed_domains": "example.com,example.org",
			"cache_for_ratio": 101,
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())

	// LIST + DELETE
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "roles/", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"web"}, resp.Data["keys"])
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)

	// allow_any_name=true 时无需 allowed_domains
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/any",
		Storage: storage,
		Data: map[string]interface{}{
			"account":        "le",
			"allow_any_name": true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create allow_any_name role: %v", resp)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/any", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, true, resp.Data["allow_any_name"])
	require.Empty(t, resp.Data["allowed_domains"])

	// allow_any_name=false 且未传 allowed_domains 时报错
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/missing-domains",
		Storage: storage,
		Data: map[string]interface{}{
			"account":        "le",
			"allow_any_name": false,
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "allowed_domains")
}

// 部分更新不得静默重置 bool 字段：allow_bare_domains/allow_subdomains 被重置
// false 会静默收紧签发策略，disable_cache 被重置会静默恢复缓存。
// 对齐 account 路径 TestAccountPartialUpdatePreservesBools 先例。
func TestRolePartialUpdatePreservesBools(t *testing.T) {
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	})
	require.NoError(t, err)

	// 创建：三个 bool 均为 true
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":            "le",
			"allowed_domains":    "example.com",
			"allow_bare_domains": true,
			"allow_subdomains":   true,
			"disable_cache":      true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create: %v", resp)

	// 部分更新：仅改 allowed_domains 与 cache_for_ratio，不提及三个 bool
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":         "le",
			"allowed_domains": "example.com,example.org",
			"cache_for_ratio": 50,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "partial update: %v", resp)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)
	// 未提及的 bool 字段保留旧值
	require.Equal(t, true, resp.Data["allow_bare_domains"])
	require.Equal(t, true, resp.Data["allow_subdomains"])
	require.Equal(t, true, resp.Data["disable_cache"])
	require.Equal(t, 50, resp.Data["cache_for_ratio"])

	// 显式覆盖走 ok=true 路径：显式 false 可覆盖回 false
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":         "le",
			"allowed_domains": "example.com,example.org",
			"disable_cache":   false,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "explicit false: %v", resp)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, false, resp.Data["disable_cache"])

	// 显式 true 再度生效
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":         "le",
			"allowed_domains": "example.com,example.org",
			"disable_cache":   true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "explicit true: %v", resp)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, true, resp.Data["disable_cache"])
}

func TestRoleDisableCertReuseField(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 直写夹具（含 account），绕开 pathRoleWrite 的 account 存在性校验
	putRoleFixture(t, ctx, storage, &roleEntry{
		Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70, DisableCertReuse: true,
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, true, resp.Data["disable_cert_reuse"])

	// 显式改回 false（GetOk 对显式 false 也返回 ok=true）
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/web", Storage: storage,
		Data: map[string]interface{}{"disable_cert_reuse": false},
	})
	require.NoError(t, err)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	})
	require.NoError(t, err)
	require.Equal(t, false, resp.Data["disable_cert_reuse"])
}
