package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateTokenEnv 清空所有会影响 token 解析的环境变量，避免用例间及宿主环境交叉污染。
// 调用方需先调用 t.Setenv("HOME", ...) 指定隔离的家目录。
func isolateTokenEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"BAO_TOKEN", "VAULT_TOKEN",
		"BAO_TOKEN_PATH", "VAULT_TOKEN_PATH",
		"BAO_CONFIG_PATH", "VAULT_CONFIG_PATH",
	} {
		t.Setenv(key, "")
	}
}

// newTestClient 以固定地址构造 Client，避免触发真实网络连接。
func newTestClient(t *testing.T) (*Client, error) {
	t.Helper()
	return NewClient(Config{
		Address: "http://127.0.0.1:8200",
		Mount:   "acme",
	})
}

// 内部 helper：默认从 ~/.vault-token 读取（含尾随换行）。
func TestTokenFromInternalHelperDefaultPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	isolateTokenEnv(t)

	require.NoError(t, os.WriteFile(filepath.Join(dir, ".vault-token"), []byte("helper-token\n"), 0o600))

	cli, err := newTestClient(t)
	require.NoError(t, err)
	assert.Equal(t, "helper-token", cli.RawClient().Token())
}

// 内部 helper：BAO_TOKEN_PATH 覆盖默认路径。
func TestTokenFromInternalHelperCustomPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	isolateTokenEnv(t)

	custom := filepath.Join(dir, "custom-token")
	require.NoError(t, os.WriteFile(custom, []byte("custom-token-value\n"), 0o600))
	t.Setenv("BAO_TOKEN_PATH", custom)

	cli, err := newTestClient(t)
	require.NoError(t, err)
	assert.Equal(t, "custom-token-value", cli.RawClient().Token())
}

// 优先级：显式 env（BAO_TOKEN）优先于 helper 文件。
func TestTokenEnvTakesPrecedenceOverHelper(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	isolateTokenEnv(t)

	require.NoError(t, os.WriteFile(filepath.Join(dir, ".vault-token"), []byte("helper-token\n"), 0o600))
	t.Setenv("BAO_TOKEN", "env-token")

	cli, err := newTestClient(t)
	require.NoError(t, err)
	assert.Equal(t, "env-token", cli.RawClient().Token())
}

// helper 中无 token 时 fail-fast，错误信息应带登录指引。
func TestTokenMissingFailsFast(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	isolateTokenEnv(t)

	_, err := newTestClient(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "未找到 OpenBao token")
	assert.Contains(t, err.Error(), "bao CLI 完成登录")
}

// 外部 helper：~/.bao 配置 token_helper 指向脚本，执行 get 获取 token。
func TestTokenFromExternalHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("外部 helper 脚本仅在类 Unix 平台测试")
	}

	dir := t.TempDir()
	t.Setenv("HOME", dir)
	isolateTokenEnv(t)
	t.Setenv("TOKEN_FROM_HELPER", "external-token")

	script := filepath.Join(dir, "token-helper.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho \"$TOKEN_FROM_HELPER\"\n"), 0o700))

	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".bao"),
		[]byte("token_helper = \""+script+"\"\n"),
		0o600,
	))

	cli, err := newTestClient(t)
	require.NoError(t, err)
	assert.Equal(t, "external-token", cli.RawClient().Token())
}

// 外部 helper 执行失败时应返回带 stderr 摘要的错误。
func TestTokenFromExternalHelperFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("外部 helper 脚本仅在类 Unix 平台测试")
	}

	dir := t.TempDir()
	t.Setenv("HOME", dir)
	isolateTokenEnv(t)

	script := filepath.Join(dir, "fail-helper.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\necho boom >&2\nexit 1\n"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".bao"),
		[]byte("token_helper = \""+script+"\"\n"),
		0o600,
	))

	_, err := newTestClient(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "读取 bao CLI token helper 失败")
	assert.Contains(t, err.Error(), "boom")
}
