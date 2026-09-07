package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIDNSProviderPartialUpdate(t *testing.T) {
	mux := http.NewServeMux()

	storedProvider := map[string]any{
		"type":                 "cloudflare",
		"credentials_ref":      map[string]any{"mount": "secret", "path": "dns/cf"},
		"propagation_timeout":  120 * float64(time.Second),
		"polling_interval":     2 * float64(time.Second),
		"skip_propagation_check": false,
		"propagation_wait":     float64(0),
		"resolvers":            []any{"1.1.1.1:53"},
	}

	mux.HandleFunc("/v1/acme/dns-providers/cf", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			resp := map[string]any{
				"data": storedProvider,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			var updateData map[string]any
			_ = json.NewDecoder(r.Body).Decode(&updateData)
			for k, v := range updateData {
				storedProvider[k] = v
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 增量修改：仅传入 --resolvers 和 --skip-check，不传 --type 与 --cred-path
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"provider", "set", "cf",
		"--resolvers", "223.5.5.5:53,119.29.29.29:53",
		"--skip-check",
		"--prop-wait", "60",
	})
	err := cmd.ExecuteContext(context.Background())
	require.NoError(t, err)

	// 验证旧的 type 和 credentials_ref 仍被保留，新的配置已合并
	assert.Equal(t, "cloudflare", storedProvider["type"])
	assert.Equal(t, true, storedProvider["skip_propagation_check"])
	assert.Equal(t, float64(60), storedProvider["propagation_wait"])
	assert.Equal(t, []any{"223.5.5.5:53", "119.29.29.29:53"}, storedProvider["resolvers"])
}
