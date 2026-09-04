package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLICertIssueFlow(t *testing.T) {
	mux := http.NewServeMux()

	// 模拟 /v1/acme/certs/my-role
	mux.HandleFunc("/v1/acme/certs/my-role", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		// 默认异步返回 job_id
		resp := map[string]any{
			"data": map[string]any{
				"job_id":      "job-test-cli",
				"common_name": body["common_name"],
				"poll_path":   "jobs/job-test-cli",
				"created_at":  "2026-09-05T12:00:00Z",
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 模拟 /v1/acme/jobs/job-test-cli
	mux.HandleFunc("/v1/acme/jobs/job-test-cli", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"id":          "job-test-cli",
				"status":      string(api.JobCompleted),
				"common_name": "cli.example.com",
				"cert": map[string]any{
					"certificate": "-----BEGIN CERTIFICATE-----\nmock-cert\n-----END CERTIFICATE-----",
					"private_key": "-----BEGIN EC PRIVATE KEY-----\nmock-key\n-----END EC PRIVATE KEY-----",
				},
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmpDir := t.TempDir()
	certOut := filepath.Join(tmpDir, "cert.pem")
	keyOut := filepath.Join(tmpDir, "key.pem")

	// 测试 CLI 命令
	cmd := rootCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"cert", "issue", "my-role",
		"--cn", "cli.example.com",
		"--out-cert", certOut,
		"--out-key", keyOut,
	})

	err := cmd.ExecuteContext(context.Background())
	require.NoError(t, err)

	// 验证文件保存
	certData, err := os.ReadFile(certOut)
	require.NoError(t, err)
	assert.Contains(t, string(certData), "mock-cert")

	keyData, err := os.ReadFile(keyOut)
	require.NoError(t, err)
	assert.Contains(t, string(keyData), "mock-key")
}
