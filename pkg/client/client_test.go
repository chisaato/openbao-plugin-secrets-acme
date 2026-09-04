package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientBasics(t *testing.T) {
	mux := http.NewServeMux()

	// Mock /v1/acme/accounts/test-acc
	mux.HandleFunc("/v1/acme/accounts/test-acc", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			resp := map[string]any{
				"data": map[string]any{
					"name":                     "test-acc",
					"server_url":               body["server_url"],
					"contact":                  body["contact"],
					"terms_of_service_agreed": true,
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		case http.MethodGet:
			resp := map[string]any{
				"data": map[string]any{
					"name":                     "test-acc",
					"server_url":               "https://acme.example.com",
					"contact":                  "mailto:test@example.com",
					"terms_of_service_agreed": true,
				},
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	})

	// Mock /v1/acme/jobs/job-123
	jobPollCount := 0
	mux.HandleFunc("/v1/acme/jobs/job-123", func(w http.ResponseWriter, r *http.Request) {
		jobPollCount++
		status := api.JobProcessing
		var cert *api.JobCertSnapshot
		if jobPollCount >= 2 {
			status = api.JobCompleted
			cert = &api.JobCertSnapshot{
				CertificatePEM: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
			}
		}
		resp := map[string]any{
			"data": map[string]any{
				"id":          "job-123",
				"status":      string(status),
				"common_name": "example.com",
				"cert":        cert,
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cli, err := NewClient(Config{
		Address: srv.URL,
		Token:   "root",
		Mount:   "acme",
	})
	require.NoError(t, err)

	ctx := context.Background()

	// 1. Account register
	acc, err := cli.RegisterAccount(ctx, "test-acc", api.Account{
		ServerURL: "https://acme.example.com",
		Contact:   "mailto:test@example.com",
		TOSAgreed: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "test-acc", acc.Name)
	assert.Equal(t, "https://acme.example.com", acc.ServerURL)

	// 2. Account get
	accGet, err := cli.GetAccount(ctx, "test-acc")
	require.NoError(t, err)
	assert.Equal(t, "mailto:test@example.com", accGet.Contact)

	// 3. Poll job
	polledJob, err := cli.PollJobUntilDone(ctx, "job-123", 10*time.Millisecond, nil)
	require.NoError(t, err)
	assert.Equal(t, api.JobCompleted, polledJob.Status)
	assert.NotNil(t, polledJob.Cert)
	assert.Contains(t, polledJob.Cert.CertificatePEM, "fake")
}
