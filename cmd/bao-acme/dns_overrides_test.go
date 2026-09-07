package main

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

func TestCLIDNSOverridesAndResolvers(t *testing.T) {
	mux := http.NewServeMux()

	var recordedProviderData map[string]any
	var recordedIssueData map[string]any

	// mock set provider
	mux.HandleFunc("/v1/acme/dns-providers/cf", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&recordedProviderData)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet {
			resp := map[string]any{
				"data": map[string]any{
					"type":                   "cloudflare",
					"skip_propagation_check": true,
					"propagation_wait":       60,
					"resolvers":              []string{"223.5.5.5:53"},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	})

	// mock issue cert
	mux.HandleFunc("/v1/acme/certs/web", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&recordedIssueData)
			resp := map[string]any{
				"data": map[string]any{
					"job_id":      "job-override-test",
					"common_name": "example.com",
					"status":      "pending",
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1. CLI provider set 支持 --resolvers, --skip-check, --prop-wait
	cmdProv := newRootCmd()
	cmdProv.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"provider", "set", "cf",
		"--type", "cloudflare",
		"--cred-path", "dns/cf",
		"--skip-check",
		"--prop-wait", "60",
		"--resolvers", "223.5.5.5:53,1.1.1.1:53",
	})
	require.NoError(t, cmdProv.ExecuteContext(context.Background()))
	assert.Equal(t, true, recordedProviderData["skip_propagation_check"])
	assert.Equal(t, float64(60), recordedProviderData["propagation_wait"])
	assert.Equal(t, []any{"223.5.5.5:53", "1.1.1.1:53"}, recordedProviderData["resolvers"])

	// 2. CLI cert issue 支持单次覆盖 --skip-check, --prop-wait, --resolvers
	cmdIssue := newRootCmd()
	buf := new(bytes.Buffer)
	cmdIssue.SetOut(buf)
	cmdIssue.SetErr(buf)
	cmdIssue.SetArgs([]string{
		"--address", srv.URL,
		"--token", "t",
		"cert", "issue", "web",
		"-d", "example.com",
		"--no-wait",
		"--skip-check",
		"--prop-wait", "30",
		"--resolvers", "223.5.5.5:53",
	})
	require.NoError(t, cmdIssue.ExecuteContext(context.Background()))
	assert.Equal(t, "example.com", recordedIssueData["common_name"])
	assert.Equal(t, true, recordedIssueData["skip_propagation_check"])
	assert.Equal(t, float64(30), recordedIssueData["propagation_wait"])
	assert.Equal(t, []any{"223.5.5.5:53"}, recordedIssueData["resolvers"])
}
