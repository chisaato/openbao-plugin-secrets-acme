package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCLICertKVCommands：通过 httptest 拦截插件写请求，校验三个 KV 子命令的
// 参数解析、请求路径与请求体拼装。单参数形态用 sync 覆盖（先 GET certs/id/{id}
// 解析出 role/cn），双参数形态覆盖 link/unlink 与 link 的空字段省略。
func TestCLICertKVCommands(t *testing.T) {
	mux := http.NewServeMux()

	var (
		mu       sync.Mutex
		captured = map[string]map[string]any{}
	)
	record := func(key string, body map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		captured[key] = body
	}

	// 单参数寻址：GET certs/id/{id}。
	mux.HandleFunc("/v1/acme/certs/id/cert-id-1234", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":          "cert-id-12345678abcd",
				"common_name": "misakacloud.dev",
				"role":        "web",
			},
		})
	})

	// sync（单参数解析后落到 role+cn 形态）。
	mux.HandleFunc("/v1/acme/certs/web/misakacloud.dev/kv/sync", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		record("sync", body)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"output_kv_status": "written",
			"output_kv_mount":  "secret",
			"output_kv_path":   "secret/certs/abc123",
		}})
	})

	// link（双参数，带 mount/path）。
	mux.HandleFunc("/v1/acme/certs/web/example.com/kv/link", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		record("link", body)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"output_kv_status": "written",
			"output_kv_mount":  "secret2",
			"output_kv_path":   "secret2/my/cert",
		}})
	})

	// link（双参数，未传 mount/path：请求体应不含这两个键）。
	mux.HandleFunc("/v1/acme/certs/web/nomount.example.com/kv/link", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		record("link_nomount", body)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"output_kv_status": "written",
			"output_kv_mount":  "from-role",
			"output_kv_path":   "from-role/certs/xyz",
		}})
	})

	// unlink（双参数，--delete-kv）。
	mux.HandleFunc("/v1/acme/certs/web/example.com/kv/unlink", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		record("unlink", body)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"unlinked":   true,
			"kv_deleted": true,
		}})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	run := func(args ...string) (string, error) {
		cmd := NewRootCmd()
		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		// KV mount 用子命令专属的 --kv-mount，与根持久 --mount（插件挂载路径）
		// 不再同名冲突；此处不注入根 --mount，依赖默认插件 mount "acme"。
		full := append([]string{"--address", srv.URL, "--token", "t"}, args...)
		cmd.SetArgs(full)
		err := cmd.ExecuteContext(context.Background())
		return buf.String(), err
	}

	// 1. cert kv-sync <cert_id> --force：单参数解析 + force 透传 + 表格字段。
	out, err := run("cert", "kv-sync", "cert-id-1234", "--force")
	require.NoError(t, err)
	assert.Contains(t, out, "KV Status:  written")
	assert.Contains(t, out, "KV Mount:   secret")
	assert.Contains(t, out, "KV Path:    secret/certs/abc123")
	assert.Equal(t, true, captured["sync"]["force"])

	// 2. cert kv-link web example.com --kv-mount secret2 --path my/cert --force。
	out, err = run("cert", "kv-link", "web", "example.com", "--kv-mount", "secret2", "--path", "my/cert", "--force")
	require.NoError(t, err)
	assert.Contains(t, out, "KV Mount:   secret2")
	assert.Contains(t, out, "KV Path:    secret2/my/cert")
	assert.Equal(t, "secret2", captured["link"]["mount"])
	assert.Equal(t, "my/cert", captured["link"]["path"])
	assert.Equal(t, true, captured["link"]["force"])

	// 3. cert kv-link 未传 mount/path：空串字段不应写入请求体。
	_, err = run("cert", "kv-link", "web", "nomount.example.com")
	require.NoError(t, err)
	_, hasMount := captured["link_nomount"]["mount"]
	_, hasPath := captured["link_nomount"]["path"]
	assert.False(t, hasMount, "空 mount 不应写入请求体")
	assert.False(t, hasPath, "空 path 不应写入请求体")
	assert.Equal(t, false, captured["link_nomount"]["force"])

	// 4. cert kv-unlink web example.com --delete-kv：请求体与表格输出。
	out, err = run("cert", "kv-unlink", "web", "example.com", "--delete-kv")
	require.NoError(t, err)
	assert.Contains(t, out, "Unlinked:   true")
	assert.Contains(t, out, "KV Deleted: true")
	assert.Equal(t, true, captured["unlink"]["delete_kv"])
}

// TestCLICertKVSyncIDNotFound：单参数形态下 GetCertByID 的原错误必须原样返回，
// 不得被 KV 同步的错误包装吞掉。
func TestCLICertKVSyncIDNotFound(t *testing.T) {
	mux := http.NewServeMux()
	// 未注册 certs/id/unknown，OpenBao client 读到 404 → GetCertByID 返回 not found。
	mux.HandleFunc("/v1/acme/certs/id/unknown", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"not found"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--address", srv.URL, "--token", "t", "--mount", "acme",
		"cert", "kv-sync", "unknown"})
	err := cmd.ExecuteContext(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `certificate with id "unknown" not found`)
}
