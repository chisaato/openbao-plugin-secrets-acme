package main

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

func TestCLITableFormattingOutputs(t *testing.T) {
	mux := http.NewServeMux()

	// 1. mock Account
	mux.HandleFunc("/v1/acme/accounts", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"keys": []string{"letsencrypt-prod"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/acme/accounts/letsencrypt-prod", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"server_url": "https://acme-v02.api.letsencrypt.org/directory",
				"contact":    "ops@example.com",
				"key_type":   "ec256",
				"dns_providers": []map[string]any{
					{"name": "cf"},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 2. mock Provider
	mux.HandleFunc("/v1/acme/dns-providers", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"keys": []string{"cf"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/acme/dns-providers/cf", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"type":                 "cloudflare",
				"propagation_timeout":  120000000000,
				"polling_interval":     2000000000,
				"propagation_wait":     5,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 3. mock Role
	mux.HandleFunc("/v1/acme/roles", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"keys": []string{"web"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/acme/roles/web", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"account":         "letsencrypt-prod",
				"allowed_domains": []string{"example.com", "*.example.com"},
				"cache_for_ratio": 80,
				"disable_cache":   false,
				"output_kv_mount": "secret",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 4. mock Certs
	mux.HandleFunc("/v1/acme/certs", func(w http.ResponseWriter, r *http.Request) {
		futureExp := time.Now().Add(60 * 24 * time.Hour).Format(time.RFC3339)
		resp := map[string]any{
			"data": map[string]any{
				"certificates": []map[string]any{
					{
						"common_name": "example.com",
						"role":        "web",
						"account":     "letsencrypt-prod",
						"not_after":   futureExp,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Account List
	cmdAcc := newRootCmd()
	bufAcc := new(bytes.Buffer)
	cmdAcc.SetOut(bufAcc)
	cmdAcc.SetArgs([]string{"--address", srv.URL, "--token", "t", "account", "list"})
	require.NoError(t, cmdAcc.ExecuteContext(context.Background()))
	assert.Contains(t, bufAcc.String(), "SERVER URL")
	assert.Contains(t, bufAcc.String(), "letsencrypt-prod")

	// Provider List
	cmdProv := newRootCmd()
	bufProv := new(bytes.Buffer)
	cmdProv.SetOut(bufProv)
	cmdProv.SetArgs([]string{"--address", srv.URL, "--token", "t", "provider", "list"})
	require.NoError(t, cmdProv.ExecuteContext(context.Background()))
	assert.Contains(t, bufProv.String(), "PROP_WAIT")
	assert.Contains(t, bufProv.String(), "cloudflare")

	// Role List
	cmdRole := newRootCmd()
	bufRole := new(bytes.Buffer)
	cmdRole.SetOut(bufRole)
	cmdRole.SetArgs([]string{"--address", srv.URL, "--token", "t", "role", "list"})
	require.NoError(t, cmdRole.ExecuteContext(context.Background()))
	assert.Contains(t, bufRole.String(), "ALLOWED DOMAINS")
	assert.Contains(t, bufRole.String(), "80%")

	// Cert List
	cmdCert := newRootCmd()
	bufCert := new(bytes.Buffer)
	cmdCert.SetOut(bufCert)
	cmdCert.SetArgs([]string{"--address", srv.URL, "--token", "t", "cert", "list"})
	require.NoError(t, cmdCert.ExecuteContext(context.Background()))
	assert.Contains(t, bufCert.String(), "COMMON NAME")
	assert.Contains(t, bufCert.String(), "Active")
}
