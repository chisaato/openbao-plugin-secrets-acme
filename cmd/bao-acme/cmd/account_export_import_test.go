package cmd

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

const testExportPrivateKey = "-----BEGIN EC PRIVATE KEY-----\nexport-key-material\n-----END EC PRIVATE KEY-----"

func TestAccountExport(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/acme/accounts/my-acc/export", func(w http.ResponseWriter, r *http.Request) {
		// 完整的导出载荷，来自 GET accounts/{name}/export
		resp := map[string]any{
			"data": map[string]any{
				"kind":                    api.AccountExportKind,
				"version":                 api.AccountExportVersion,
				"name":                    "my-acc",
				"server_url":              "https://acme.example.com/directory",
				"contact":                 "mailto:admin@example.com",
				"terms_of_service_agreed": true,
				"key_type":                "EC256",
				"private_key_pem":         testExportPrivateKey,
				"registration_json":       `{"uri":"https://acme.example.com/acct/1"}`,
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("stdout", func(t *testing.T) {
		cmd := NewRootCmd()
		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		cmd.SetArgs([]string{
			"--address", srv.URL,
			"--token", "test-token",
			"account", "export", "my-acc",
		})
		require.NoError(t, cmd.ExecuteContext(context.Background()))
		// 未指定 -o 时直接把含私钥的 JSON 打到 stdout（JSON 内换行被转义）
		assert.Contains(t, buf.String(), "private_key_pem")
		assert.Contains(t, buf.String(), "export-key-material")
	})

	t.Run("out file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "account-export.json")
		cmd := NewRootCmd()
		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		cmd.SetArgs([]string{
			"--address", srv.URL,
			"--token", "test-token",
			"account", "export", "my-acc",
			"-o", out,
		})
		require.NoError(t, cmd.ExecuteContext(context.Background()))

		data, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Contains(t, string(data), "private_key_pem")
		assert.Contains(t, string(data), "export-key-material")

		info, err := os.Stat(out)
		require.NoError(t, err)
		// 含私钥，权限必须为 0600
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})
}

func TestAccountImport(t *testing.T) {
	dir := t.TempDir()
	exportPath := filepath.Join(dir, "account-export.json")
	exp := api.AccountExport{
		Kind:             api.AccountExportKind,
		Version:          api.AccountExportVersion,
		Name:             "source-acc",
		ServerURL:        "https://acme.example.com/directory",
		Contact:          "mailto:admin@example.com",
		TOSAgreed:        true,
		KeyType:          "EC256",
		PrivateKeyPEM:    testExportPrivateKey,
		RegistrationJSON: `{"uri":"https://acme.example.com/acct/1"}`,
	}
	raw, err := json.MarshalIndent(exp, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(exportPath, raw, 0o600))

	var gotBody map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/acme/accounts/imported/import", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		resp := map[string]any{
			"data": map[string]any{
				"name":        "imported",
				"server_url":  exp.ServerURL,
				"contact":     exp.Contact,
				"key_type":    exp.KeyType,
				"verified":    true,
				"overwritten": true,
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"account", "import", "imported",
		"--file", exportPath,
		"--verify",
		"--overwrite",
	})
	require.NoError(t, cmd.ExecuteContext(context.Background()))

	require.NotNil(t, gotBody)
	// 请求体必须携带私钥与注册信息
	assert.Equal(t, testExportPrivateKey, gotBody["private_key_pem"])
	assert.Equal(t, exp.RegistrationJSON, gotBody["registration_json"])
	// verify / overwrite 开关必须透传
	assert.Equal(t, true, gotBody["verify"])
	assert.Equal(t, true, gotBody["overwrite"])
	// 命令行文本输出
	assert.Contains(t, buf.String(), "已导入")
}

func TestAccountImportInvalidFile(t *testing.T) {
	tests := []struct {
		name    string
		payload api.AccountExport
		wantErr string
	}{
		{
			name:    "wrong kind",
			payload: api.AccountExport{Kind: "not-an-export", Version: api.AccountExportVersion},
			wantErr: "不是有效的账户导出文件",
		},
		{
			name:    "future version",
			payload: api.AccountExport{Kind: api.AccountExportKind, Version: api.AccountExportVersion + 99},
			wantErr: "导出文件版本过新，请升级 CLI",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad-export.json")
			raw, err := json.MarshalIndent(tc.payload, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(p, raw, 0o600))

			cmd := NewRootCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{"account", "import", "bad", "--file", p})

			err = cmd.ExecuteContext(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			// 校验失败发生在连接 CA 之前，不应有网络依赖
			assert.Contains(t, buf.String(), tc.wantErr)
		})
	}
}
