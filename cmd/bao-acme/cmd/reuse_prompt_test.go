package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLICertReusePrompt(t *testing.T) {
	mux := http.NewServeMux()

	// mock issue cert (命中复用)
	mux.HandleFunc("/v1/acme/certs/web", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"common_name": "misakacloud.dev",
				"certificate": "-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----",
				"reused":      true,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// mock LIST certs
	mux.HandleFunc("/v1/acme/certs/web/list", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"certificates": []map[string]any{
					{
						"id":          "86c1467f25e9abcd1234",
						"cert_id":     "86c1467f25e9abcd1234",
						"common_name": "misakacloud.dev",
						"domains":     []string{"misakacloud.dev", "*.misakacloud.dev"},
						"role":        "web",
						"account":     "le",
						"not_after":   time.Now().Add(89 * 24 * time.Hour).Format(time.RFC3339),
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"cert", "issue", "web",
		"-d", "misakacloud.dev",
	})
	require.NoError(t, cmd.ExecuteContext(context.Background()))
	out := buf.String()
	// 验证打印了匹配证书表格，且没有打印证书 PEM
	assert.Contains(t, out, "86c1467f25e9")
	assert.Contains(t, out, "CERT ID")
	assert.NotContains(t, out, "-----BEGIN CERTIFICATE-----")
}
