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

func TestCLICertIssueDomainFlags(t *testing.T) {
	var receivedCN string
	var receivedAlt []any

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/acme/certs/web", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedCN, _ = body["common_name"].(string)
		receivedAlt, _ = body["alt_names"].([]any)

		resp := map[string]any{
			"data": map[string]any{
				"job_id":      "job-test-d",
				"common_name": receivedCN,
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cmd := rootCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// 使用类似 acme.sh 的 -d domain1 -d domain2 -d domain3
	cmd = newRootCmd()
	buf = new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"cert", "issue", "web",
		"-d", "example.com",
		"-d", "*.example.com",
		"-d", "api.example.com",
		"--no-wait",
	})

	err := cmd.ExecuteContext(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "example.com", receivedCN)
	assert.Len(t, receivedAlt, 2)
	assert.Equal(t, "*.example.com", receivedAlt[0])
	assert.Equal(t, "api.example.com", receivedAlt[1])
}
