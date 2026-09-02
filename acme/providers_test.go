package acme

import (
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/exec"
	"github.com/stretchr/testify/require"
)

func TestCloudflareConfigTokenOnly(t *testing.T) {
	cfg, err := cloudflareConfig(map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "tok"})
	require.NoError(t, err)
	require.Equal(t, "tok", cfg.AuthToken)
}

func TestCloudflareConfigGlobalKey(t *testing.T) {
	cfg, err := cloudflareConfig(map[string]string{
		"CLOUDFLARE_EMAIL": "a@b.c", "CLOUDFLARE_API_KEY": "gk",
	})
	require.NoError(t, err)
	require.Equal(t, "a@b.c", cfg.AuthEmail)
	require.Equal(t, "gk", cfg.AuthKey)
}

func TestCloudflareConfigMissing(t *testing.T) {
	_, err := cloudflareConfig(map[string]string{})
	require.ErrorContains(t, err, "CLOUDFLARE_DNS_API_TOKEN")
}

func TestAliDNSConfig(t *testing.T) {
	cfg, err := alidnsConfig(map[string]string{
		"ALICLOUD_ACCESS_KEY": "ak", "ALICLOUD_SECRET_KEY": "sk",
	})
	require.NoError(t, err)
	require.Equal(t, "ak", cfg.APIKey)
	require.Equal(t, "sk", cfg.SecretKey)

	_, err = alidnsConfig(map[string]string{"ALICLOUD_ACCESS_KEY": "ak"})
	require.Error(t, err)
}

func TestAliDNSConfigRAMRole(t *testing.T) {
	cfg, err := alidnsConfig(map[string]string{
		"ALICLOUD_ACCESS_KEY": "ak", "ALICLOUD_RAM_ROLE": "role",
	})
	require.NoError(t, err)
	require.Equal(t, "ak", cfg.APIKey)
	require.Equal(t, "role", cfg.RAMRole)

	// 仅 RAMRole：免 AK/SK 的独立认证路径（ECS 实例 RAM 角色），构造应通过。
	cfg, err = alidnsConfig(map[string]string{"ALICLOUD_RAM_ROLE": "role"})
	require.NoError(t, err)
	require.Equal(t, "role", cfg.RAMRole)
	_, err = newProvider(t.Context(), "alidns", providerOpts{}, map[string]string{"ALICLOUD_RAM_ROLE": "role"})
	require.NoError(t, err)

	// 全缺仍报错。
	_, err = alidnsConfig(map[string]string{})
	require.Error(t, err)
}

func TestTencentCloudConfig(t *testing.T) {
	cfg, err := tencentcloudConfig(map[string]string{
		"TENCENTCLOUD_SECRET_ID": "id", "TENCENTCLOUD_SECRET_KEY": "key",
	})
	require.NoError(t, err)
	require.Equal(t, "id", cfg.SecretID)
	require.Equal(t, "key", cfg.SecretKey)

	_, err = tencentcloudConfig(map[string]string{})
	require.Error(t, err)
}

func TestRegistryWhitelist(t *testing.T) {
	for _, name := range []string{"cloudflare", "alidns", "tencentcloud", "exec"} {
		require.Contains(t, registry, name)
	}
	_, err := newProvider(t.Context(), "dnspod", providerOpts{}, nil)
	require.ErrorContains(t, err, "alidns, cloudflare, exec, tencentcloud")
}

func TestExecConfig(t *testing.T) {
	// 缺 EXEC_PATH：报错并列出可用键。
	_, err := newProvider(t.Context(), "exec", providerOpts{}, nil)
	require.ErrorContains(t, err, "EXEC_PATH")

	// EXEC_PATH 命中：构造成功且 Program 绑定。
	p, err := newProvider(t.Context(), "exec", providerOpts{}, map[string]string{"EXEC_PATH": "/bin/true"})
	require.NoError(t, err)
	require.IsType(t, &exec.DNSProvider{}, p)

	// 调参覆盖默认值（dns-provider 的 propagation_timeout/polling_interval）。
	p, err = newProvider(t.Context(), "exec", providerOpts{
		PropagationTimeout: 7 * time.Second,
		PollingInterval:    3 * time.Second,
	}, map[string]string{"EXEC_PATH": "/bin/true"})
	require.NoError(t, err)
	tp := p.(challenge.ProviderTimeout)
	timeout, interval := tp.Timeout()
	require.Equal(t, 7*time.Second, timeout)
	require.Equal(t, 3*time.Second, interval)
}
