package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIRolePartialUpdate(t *testing.T) {
	var receivedBody map[string]any

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/acme/roles/web", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// 仅覆盖 disable-reuse 和 cache-ratio 两个字段（account 为位置参数）
	cmd.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"role", "set", "web", "le",
		"--disable-reuse=true",
		"--cache-ratio", "50",
	})

	err := cmd.ExecuteContext(context.Background())
	require.NoError(t, err)

	// 验证发往 openbao 的 payload 只包含显式传的 flag + 位置参数 account
	assert.Equal(t, true, receivedBody["disable_cert_reuse"])
	assert.Equal(t, float64(50), receivedBody["cache_for_ratio"])
	// account 为位置参数，始终随请求发送
	assert.Equal(t, "le", receivedBody["account"])
	assert.NotContains(t, receivedBody, "allowed_domains")
	assert.NotContains(t, receivedBody, "allow_bare_domains")
	assert.NotContains(t, receivedBody, "allow_subdomains")
}
