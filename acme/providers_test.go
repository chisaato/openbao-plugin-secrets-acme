package acme

import (
	"testing"

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
	for _, name := range []string{"cloudflare", "alidns", "tencentcloud"} {
		require.Contains(t, registry, name)
	}
	_, err := newProvider(t.Context(), "dnspod", providerOpts{}, nil)
	require.ErrorContains(t, err, "alidns, cloudflare, tencentcloud")
}
