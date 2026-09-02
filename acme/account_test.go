package acme

import (
	"testing"

	"github.com/go-acme/lego/v5/registration"
	"github.com/stretchr/testify/require"
)

// 编译期断言：legoUser 实现 lego 账户接口。
var _ registration.User = (*legoUser)(nil)

func TestKeyTypesWhitelist(t *testing.T) {
	for _, kt := range []string{"EC256", "EC384", "RSA2048", "RSA4096", "RSA8192"} {
		require.Contains(t, keyTypes, kt)
	}
	require.NotContains(t, keyTypes, "RSA1024")
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	for name, kt := range keyTypes {
		t.Run(name, func(t *testing.T) {
			key, pemStr, err := generatePrivateKeyPEM(kt)
			require.NoError(t, err)
			require.Contains(t, pemStr, "BEGIN PRIVATE KEY")

			parsed, err := parsePrivateKeyPEM(pemStr)
			require.NoError(t, err)

			// 公钥部分必须一致
			require.Equal(t, key.Public(), parsed.Public())
		})
	}
}

func TestParsePrivateKeyPEMInvalid(t *testing.T) {
	_, err := parsePrivateKeyPEM("not a pem")
	require.Error(t, err)
}
