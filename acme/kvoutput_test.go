package acme

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

type recordingKVWriter struct {
	writes []kvWrite
}

type kvWrite struct {
	clientToken, mount, path string
	data                     map[string]interface{}
}

func (w *recordingKVWriter) Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error {
	w.writes = append(w.writes, kvWrite{clientToken, mount, path, data})
	return nil
}

func TestSanitizeCN(t *testing.T) {
	require.Equal(t, "_wildcard.example.com", sanitizeCN("*.example.com"))
	require.Equal(t, "www.example.com", sanitizeCN("www.example.com"))
	require.Equal(t, "a_b.example.com", sanitizeCN("a/b.example.com"))
}

func TestOutputKVPath(t *testing.T) {
	require.Equal(t, "certs/web/_wildcard.example.com", outputKVPath("web", "*.example.com"))
	require.Equal(t, "certs/web/www.example.com", outputKVPath("web", "www.example.com"))
}

func TestWriteCertOutput(t *testing.T) {
	b, _ := testBackendConfig(t)
	w := &recordingKVWriter{}
	b.kvWriter = w

	// 未配置 output_kv_mount → no-op
	path, err := b.writeCertOutput(context.Background(), &logical.Request{ClientToken: "tok"},
		"web", &roleEntry{}, "a.com",
		&cacheEntry{CertificatePEM: "C", PrivateKeyPEM: "K"})
	require.NoError(t, err)
	require.Equal(t, "", path)
	require.Empty(t, w.writes)

	// 配置后写入：证书用有效 PEM 夹具，以断言 not_before/not_after
	// （整秒 UTC 时间，避免 RFC3339 截断亚秒导致断言歧义）
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	certPEM := selfSignedCertFor(t, notBefore, notAfter)
	path, err = b.writeCertOutput(context.Background(), &logical.Request{ClientToken: "tok"},
		"web", &roleEntry{OutputKVMount: "kv-certs"}, "*.example.com",
		&cacheEntry{CertificatePEM: certPEM, PrivateKeyPEM: "K", IssuerCertificatePEM: "I",
			Domains: []string{"*.example.com"}})
	require.NoError(t, err)
	require.Equal(t, "certs/web/_wildcard.example.com", path)
	require.Len(t, w.writes, 1)
	// 传递调用者 token
	require.Equal(t, "tok", w.writes[0].clientToken)
	require.Equal(t, "kv-certs", w.writes[0].mount)
	require.Equal(t, certPEM, w.writes[0].data["certificate"])
	require.Equal(t, "K", w.writes[0].data["private_key"])
	require.Equal(t, "I", w.writes[0].data["issuer_cert"])
	require.Equal(t, []string{"*.example.com"}, w.writes[0].data["domains"])
	// 有效期：RFC3339 可解析且等于夹具证书的 NotBefore/NotAfter（UTC）
	nb, ok := w.writes[0].data["not_before"].(string)
	require.True(t, ok, "not_before 须为 RFC3339 字符串")
	na, ok := w.writes[0].data["not_after"].(string)
	require.True(t, ok, "not_after 须为 RFC3339 字符串")
	parsedNB, err := time.Parse(time.RFC3339, nb)
	require.NoError(t, err)
	parsedNA, err := time.Parse(time.RFC3339, na)
	require.NoError(t, err)
	require.True(t, parsedNB.Equal(notBefore), "not_before=%s 须等于夹具 NotBefore", nb)
	require.True(t, parsedNA.Equal(notAfter), "not_after=%s 须等于夹具 NotAfter", na)
}

// newKVPutServer 模拟 KVv2 Put 端点（/v1/{mount}/data/{path}），
// 校验调用者 token 透传；capture 由测试填充以检视请求。
func newKVPutServer(t *testing.T, capture *map[string]interface{}) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/kv-certs/data/certs/web/www.example.com", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "fake-token" {
			t.Errorf("clientToken 未透传: got %q", got)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("请求体解析失败: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		*capture = body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"created_time":"2026-01-01T00:00:00Z","version":1}}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestAPIKVWriterPut(t *testing.T) {
	var capture map[string]interface{}
	ts := newKVPutServer(t, &capture)
	t.Setenv("BAO_ADDR", ts.URL)

	w := &apiKVWriter{}
	err := w.Write(context.Background(), "fake-token", "kv-certs", "certs/web/www.example.com",
		map[string]interface{}{"certificate": "C"})
	require.NoError(t, err)
	require.Equal(t, "C", capture["data"].(map[string]interface{})["certificate"])
}

func TestAPIKVWriterErrorContainsMountPath(t *testing.T) {
	// 指向不存在的地址：连接失败错误仍须可定位 mount/path。
	t.Setenv("BAO_ADDR", "http://127.0.0.1:1")

	w := &apiKVWriter{}
	err := w.Write(context.Background(), "tok", "kv-certs", "certs/web/www.example.com",
		map[string]interface{}{"certificate": "C"})
	require.Error(t, err)
	require.ErrorContains(t, err, "kv-certs/certs/web/www.example.com")
}
