package acme

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveKeysExplicitMapping(t *testing.T) {
	raw := map[string]string{"cf_token": "s3cret", "extra": "x"}
	ref := credentialsRef{Keys: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "cf_token"}}
	got := resolveKeys(raw, ref, []string{"CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_ZONE_API_TOKEN"})
	require.Equal(t, map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "s3cret"}, got)
}

func TestResolveKeysSameNameFallback(t *testing.T) {
	raw := map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "tok", "ALICLOUD_SECRET_KEY": "sk"}
	got := resolveKeys(raw, credentialsRef{}, []string{
		"CLOUDFLARE_DNS_API_TOKEN", "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY",
	})
	require.Equal(t, map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
		"ALICLOUD_SECRET_KEY":      "sk",
	}, got)
}

func TestRefKVVersionDefault(t *testing.T) {
	require.Equal(t, "2", (&credentialsRef{}).kvVersion())
	require.Equal(t, "1", (&credentialsRef{KVVersion: "1"}).kvVersion())
}

// newDeletedKVServer 模拟 OpenBao：KVv2 软删除响应（data 为 null 但 metadata
// 仍在，库不报错、KVSecret.Data 为 nil）与 KVv1 空数据响应（秘密存在但无键，
// 库同样不报错）。token 校验锁定插件语义：请求以插件进程 env 注入的
// BAO_TOKEN 身份发出，调用者 ClientToken（core 哈希后传给插件）不得透传。
// deletion_time 同时充当"响应内容不得泄漏进错误信息"的断言标记。
const pluginEnvToken = "plugin-env-token"

func newDeletedKVServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/creds", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != pluginEnvToken {
			t.Errorf("应以插件 env token 身份请求: got %q", got)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":null,"metadata":{"created_time":"2026-01-01T00:00:00Z","deletion_time":"2026-01-02T00:00:00Z","destroyed":false,"version":1}}}`))
	})
	mux.HandleFunc("/v1/kv/creds", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestLoadKVV2DeletedSecretReturnsError(t *testing.T) {
	ts := newDeletedKVServer(t)
	t.Setenv("BAO_ADDR", ts.URL)
	t.Setenv("BAO_TOKEN", pluginEnvToken)

	loader := &apiCredentialLoader{}
	ref := credentialsRef{Mount: "secret", Path: "creds"} // kv_version 默认 2，version 0=最新
	_, err := loader.Load(context.Background(), "hashed-caller-token", ref)
	require.Error(t, err, "软删除的 KVv2 秘密不得静默返回空凭据")
	require.ErrorContains(t, err, "secret/data/creds", "错误信息须可定位 mount/path")
	require.ErrorContains(t, err, "deleted")
	require.NotContains(t, err.Error(), "2026-01-02", "错误信息不得回显响应内容")
}

func TestLoadKVV2DeletedVersionReturnsError(t *testing.T) {
	ts := newDeletedKVServer(t)
	t.Setenv("BAO_ADDR", ts.URL)
	t.Setenv("BAO_TOKEN", pluginEnvToken)

	loader := &apiCredentialLoader{}
	ref := credentialsRef{Mount: "secret", Path: "creds", Version: 1}
	_, err := loader.Load(context.Background(), "hashed-caller-token", ref)
	require.Error(t, err, "软删除的指定版本不得静默返回空凭据")
	require.ErrorContains(t, err, "secret/data/creds")
	require.ErrorContains(t, err, "version 1")
	require.ErrorContains(t, err, "deleted")
	require.NotContains(t, err.Error(), "2026-01-02")
}

func TestLoadKVV1NilDataReturnsError(t *testing.T) {
	ts := newDeletedKVServer(t)
	t.Setenv("BAO_ADDR", ts.URL)
	t.Setenv("BAO_TOKEN", pluginEnvToken)

	loader := &apiCredentialLoader{}
	ref := credentialsRef{Mount: "kv", Path: "creds", KVVersion: "1"}
	_, err := loader.Load(context.Background(), "hashed-caller-token", ref)
	require.Error(t, err, "KVv1 空数据时不得静默返回空凭据")
	require.ErrorContains(t, err, "kv/creds", "错误信息须可定位 mount/path")
	require.ErrorContains(t, err, "deleted")
}
