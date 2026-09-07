package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIJobPruneAndListFormatting(t *testing.T) {
	mux := http.NewServeMux()

	deletedIDs := make(map[string]bool)

	// mock LIST jobs
	mux.HandleFunc("/v1/acme/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// 返回 job 列表
			keys := []string{"job-comp", "job-fail", "job-proc"}
			var activeKeys []string
			for _, k := range keys {
				if !deletedIDs[k] {
					activeKeys = append(activeKeys, k)
				}
			}
			resp := map[string]any{
				"data": map[string]any{
					"keys": activeKeys,
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	})

	// mock GET & DELETE jobs/<id>
	mux.HandleFunc("/v1/acme/jobs/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/acme/jobs/")
		if r.Method == http.MethodDelete {
			deletedIDs[id] = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet {
			if deletedIDs[id] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			nowStr := time.Now().Add(-10 * time.Minute).Format(time.RFC3339)
			var status string
			var errMsg string
			switch id {
			case "job-comp":
				status = "completed"
			case "job-fail":
				status = "failed"
				errMsg = "cloudflare: 81058"
			case "job-proc":
				status = "processing"
			}
			resp := map[string]any{
				"data": map[string]any{
					"id":          id,
					"role":        "web",
					"status":      status,
					"common_name": "example.com",
					"updated_at":  nowStr,
					"created_at":  nowStr,
					"error":       errMsg,
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1. 测试 job list tabwriter 排版
	cmdList := newRootCmd()
	bufList := new(bytes.Buffer)
	cmdList.SetOut(bufList)
	cmdList.SetErr(bufList)
	cmdList.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"job", "list",
	})
	err := cmdList.ExecuteContext(context.Background())
	require.NoError(t, err)
	listOut := bufList.String()
	assert.Contains(t, listOut, "JOB ID")
	assert.Contains(t, listOut, "STATUS")
	assert.Contains(t, listOut, "job-comp")
	assert.Contains(t, listOut, "job-fail")
	assert.Contains(t, listOut, "job-proc")

	// 2. 测试 job prune --failed-only -y
	cmdPrune := newRootCmd()
	bufPrune := new(bytes.Buffer)
	cmdPrune.SetOut(bufPrune)
	cmdPrune.SetErr(bufPrune)
	cmdPrune.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"job", "prune",
		"--failed-only",
		"-y",
	})
	err = cmdPrune.ExecuteContext(context.Background())
	require.NoError(t, err)
	pruneOut := bufPrune.String()
	assert.Contains(t, pruneOut, "已清理 1 个 Job")
	assert.Contains(t, pruneOut, "job-fail")
	assert.True(t, deletedIDs["job-fail"])
	assert.False(t, deletedIDs["job-comp"], "job-comp 不应被清理")
	assert.False(t, deletedIDs["job-proc"], "processing 不应被清理")

	// 3. 测试 job prune 全量 -y
	cmdPruneAll := newRootCmd()
	bufPruneAll := new(bytes.Buffer)
	cmdPruneAll.SetOut(bufPruneAll)
	cmdPruneAll.SetErr(bufPruneAll)
	cmdPruneAll.SetArgs([]string{
		"--address", srv.URL,
		"--token", "test-token",
		"--mount", "acme",
		"job", "prune",
		"-y",
	})
	err = cmdPruneAll.ExecuteContext(context.Background())
	require.NoError(t, err)
	assert.True(t, deletedIDs["job-comp"], "job-comp 应该被清理")
	assert.False(t, deletedIDs["job-proc"], "processing 永远不应被清理")
}
