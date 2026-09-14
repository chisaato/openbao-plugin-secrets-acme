package cmd

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
		"type":                   "cloudflare",
		"credentials_ref":        map[string]any{"mount": "secret", "path": "dns/cf"},
		"propagation_timeout":    120 * float64(time.Second),
		"polling_interval":       2 * float64(time.Second),
		"skip_propagation_check": false,
		"propagation_wait":       float64(0),
		"resolvers":              []any{"1.1.1.1:53"},
	}

	var recordedUpdate map[string]any

	mux.HandleFunc("/v1/acme/dns-providers/cf", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			resp := map[string]any{
				"data": storedProvider,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&recordedUpdate)
			for k, v := range recordedUpdate {
				storedProvider[k] = v
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 增量修改：仅传入 --resolvers 和 --skip-check，不传 --type 与 --cred-path
	cmd := NewRootCmd()
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

	// 请求体使用扁平标量凭据字段，且不再发出 credentials_ref 嵌套对象
	require.NotNil(t, recordedUpdate)
	assert.Equal(t, "secret", recordedUpdate["credentials_mount"])
	assert.Equal(t, "dns/cf", recordedUpdate["credentials_path"])
	_, hasNested := recordedUpdate["credentials_ref"]
	assert.False(t, hasNested, "请求体不应再包含 credentials_ref 嵌套对象")

	// 验证旧的 type 和存量凭据被保留，新的配置已合并
	assert.Equal(t, "cloudflare", storedProvider["type"])
	assert.Equal(t, "dns/cf", storedProvider["credentials_path"])
	assert.Equal(t, true, storedProvider["skip_propagation_check"])
	assert.Equal(t, float64(60), storedProvider["propagation_wait"])
	assert.Equal(t, []any{"223.5.5.5:53", "119.29.29.29:53"}, storedProvider["resolvers"])
}
