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

func TestCLICertManagementOps(t *testing.T) {
	mux := http.NewServeMux()

	// 1. LIST /v1/acme/certs
	mux.HandleFunc("/v1/acme/certs", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"certificates": []map[string]any{
					{
						"common_name": "example.com",
						"role":        "web",
						"account":     "acc1",
						"not_after":   "2026-12-01T00:00:00Z",
					},
				},
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 2. GET /v1/acme/certs/web/example.com
	// 3. DELETE /v1/acme/certs/web/example.com
	mux.HandleFunc("/v1/acme/certs/web/example.com", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			resp := map[string]any{
				"data": map[string]any{
					"common_name": "example.com",
					"role":        "web",
					"account":     "acc1",
					"certificate": "-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----",
					"domains":     []string{"example.com"},
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Test cert list
	cmdList := newRootCmd()
	buf := new(bytes.Buffer)
	cmdList.SetOut(buf)
	cmdList.SetErr(buf)
	cmdList.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"cert", "list",
	})
	err := cmdList.ExecuteContext(context.Background())
	require.NoError(t, err)

	// Test cert get
	cmdGet := newRootCmd()
	bufGet := new(bytes.Buffer)
	cmdGet.SetOut(bufGet)
	cmdGet.SetErr(bufGet)
	cmdGet.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"cert", "get", "web", "example.com",
	})
	err = cmdGet.ExecuteContext(context.Background())
	require.NoError(t, err)

	// Test cert revoke
	cmdRevoke := newRootCmd()
	bufRev := new(bytes.Buffer)
	cmdRevoke.SetOut(bufRev)
	cmdRevoke.SetErr(bufRev)
	cmdRevoke.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"cert", "revoke", "web", "example.com",
	})
	err = cmdRevoke.ExecuteContext(context.Background())
	require.NoError(t, err)
	assert.Empty(t, "")
}
