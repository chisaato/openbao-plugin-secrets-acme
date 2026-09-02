package acme

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveKeysExplicitMapping(t *testing.T) {
	raw := map[string]string{"cf_token": "s3cret", "extra": "x"}
	ref := credentialsRef{Keys: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "cf_token"}}
	got := resolveKeys(raw, ref, []string{"CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_ZONE_API_TOKEN"})
	require.Equal(t, map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "s3cret"}, got)
}

func TestResolveKeysSameNameFallback(t *testing.T) {
	raw := map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "tok", "ALICLOUD_SECRET_KEY": "sk"}
	got := resolveKeys(raw, credentialsRef{}, []string{
		"CLOUDFLARE_DNS_API_TOKEN", "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY",
	})
	require.Equal(t, map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
		"ALICLOUD_SECRET_KEY":      "sk",
	}, got)
}

func TestRefKVVersionDefault(t *testing.T) {
	require.Equal(t, "2", (&credentialsRef{}).kvVersion())
	require.Equal(t, "1", (&credentialsRef{KVVersion: "1"}).kvVersion())
}
