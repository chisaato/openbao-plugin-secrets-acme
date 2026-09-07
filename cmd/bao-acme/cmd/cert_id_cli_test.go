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

func TestCLICertIDAndForceOperations(t *testing.T) {
	mux := http.NewServeMux()

	var recordedIssueData map[string]any
	deletedID := ""

	// mock LIST certs
	mux.HandleFunc("/v1/acme/certs", func(w http.ResponseWriter, r *http.Request) {
		futureExp := time.Now().Add(60 * 24 * time.Hour).Format(time.RFC3339)
		resp := map[string]any{
			"data": map[string]any{
				"certificates": []map[string]any{
					{
						"id":          "cert-id-12345678abcd",
						"cert_id":     "cert-id-12345678abcd",
						"common_name": "misakacloud.dev",
						"domains":     []string{"misakacloud.dev", "*.misakacloud.dev"},
						"role":        "web",
						"account":     "le-staging",
						"not_after":   futureExp,
					},
					{
						"id":          "other-id-87654321fedc",
						"cert_id":     "other-id-87654321fedc",
						"common_name": "google.com",
						"domains":     []string{"google.com"},
						"role":        "web",
						"account":     "le-staging",
						"not_after":   futureExp,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// mock GET / DELETE certs/id/{id}
	mux.HandleFunc("/v1/acme/certs/id/cert-id-1234", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedID = "cert-id-1234"
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet {
			resp := map[string]any{
				"data": map[string]any{
					"id":          "cert-id-12345678abcd",
					"common_name": "misakacloud.dev",
					"domains":     []string{"misakacloud.dev", "*.misakacloud.dev"},
					"role":        "web",
					"account":     "le-staging",
					"certificate": "-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----",
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	})

	// mock issue cert
	mux.HandleFunc("/v1/acme/certs/web", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&recordedIssueData)
		resp := map[string]any{
			"data": map[string]any{
				"job_id":      "job-force-test",
				"common_name": "misakacloud.dev",
				"status":      "pending",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1. 测试 cert list 打印 12 位短 ID
	cmdList := NewRootCmd()
	bufList := new(bytes.Buffer)
	cmdList.SetOut(bufList)
	cmdList.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"cert", "list",
	})
	require.NoError(t, cmdList.ExecuteContext(context.Background()))
	assert.Contains(t, bufList.String(), "CERT ID")
	assert.Contains(t, bufList.String(), "cert-id-1234")
	assert.Contains(t, bufList.String(), "*.misakacloud.dev")

	// 2. 测试 cert list 按域名过滤 (-d)
	cmdFilter := NewRootCmd()
	bufFilter := new(bytes.Buffer)
	cmdFilter.SetOut(bufFilter)
	cmdFilter.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"cert", "list", "-d", "sub.misakacloud.dev",
	})
	require.NoError(t, cmdFilter.ExecuteContext(context.Background()))
	assert.Contains(t, bufFilter.String(), "cert-id-1234")
	assert.NotContains(t, bufFilter.String(), "google.com")

	// 3. 测试 cert get <short_id>
	cmdGet := NewRootCmd()
	bufGet := new(bytes.Buffer)
	cmdGet.SetOut(bufGet)
	cmdGet.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"cert", "get", "cert-id-1234",
	})
	require.NoError(t, cmdGet.ExecuteContext(context.Background()))
	assert.Contains(t, bufGet.String(), "Cert ID:        cert-id-12345678abcd")
	assert.Contains(t, bufGet.String(), "misakacloud.dev, *.misakacloud.dev")

	// 4. 测试 cert revoke <short_id>
	cmdRevoke := NewRootCmd()
	cmdRevoke.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"cert", "revoke", "cert-id-1234",
	})
	require.NoError(t, cmdRevoke.ExecuteContext(context.Background()))
	assert.Equal(t, "cert-id-1234", deletedID)

	// 5. 测试 cert issue --force
	cmdIssue := NewRootCmd()
	cmdIssue.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"cert", "issue", "web",
		"-d", "misakacloud.dev",
		"--force",
		"--no-wait",
	})
	require.NoError(t, cmdIssue.ExecuteContext(context.Background()))
	assert.Equal(t, true, recordedIssueData["force"])
}

