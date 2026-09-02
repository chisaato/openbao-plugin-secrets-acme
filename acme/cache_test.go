package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func testBackendConfig(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	return b, storage
}

func selfSignedCertFor(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCacheKeyDeterministic(t *testing.T) {
	role := &roleEntry{Account: "le"}
	d1 := cacheKey(role, []string{"b.com", "a.com"})
	d2 := cacheKey(role, []string{"a.com", "b.com"})
	d3 := cacheKey(role, []string{"a.com", "c.com"})
	require.Equal(t, d1, d2) // 域名顺序无关
	require.NotEqual(t, d1, d3)
}

func TestCacheCRUDAndRefcount(t *testing.T) {
	b, storage := testBackendConfig(t)
	ctx := context.Background()
	key := cacheKey(&roleEntry{Account: "le"}, []string{"a.com"})

	// 初始无
	e, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.Nil(t, e)

	// 写入 Users=2
	require.NoError(t, b.cachePut(ctx, storage, key, &cacheEntry{
		Users: 2, Account: "le", CN: "a.com", Domains: []string{"a.com"},
		CertificatePEM: "CERT", PrivateKeyPEM: "KEY",
	}))
	e, err = b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.Equal(t, 2, e.Users)

	// 计数/清空
	n, err := b.cacheCount(ctx, storage)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	cleared, err := b.cacheClear(ctx, storage)
	require.NoError(t, err)
	require.Equal(t, 1, cleared)
	n, _ = b.cacheCount(ctx, storage)
	require.Equal(t, 0, n)
}

func TestCertNeedsRenewal(t *testing.T) {
	now := time.Now()
	// 总寿命 100h，已用 99h，ratio=70：剩余 1% < 70% → true
	old := selfSignedCertFor(t, now.Add(-99*time.Hour), now.Add(time.Hour))
	require.True(t, certNeedsRenewal(old, 70))
	// 总寿命 100h，已用 1h：剩余 99% ≥ 70% → false
	fresh := selfSignedCertFor(t, now.Add(-time.Hour), now.Add(99*time.Hour))
	require.False(t, certNeedsRenewal(fresh, 70))
	// 解析失败 → true（保守重签）
	require.True(t, certNeedsRenewal("garbage", 70))
}
