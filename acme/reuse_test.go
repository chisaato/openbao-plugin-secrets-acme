package acme

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWildcardCovers(t *testing.T) {
	cases := []struct {
		pattern, domain string
		want            bool
	}{
		{"*.example.com", "sub.example.com", true},    // 单层标签覆盖
		{"*.example.com", "example.com", false},       // 裸域不被覆盖
		{"*.example.com", "a.b.example.com", false},   // 多级子域不被覆盖（正确性边界）
		{"*.example.com", "*.example.com", true},      // 同 pattern 相等（精确命中亦由 domainCovered 承担）
		{"sub.example.com", "sub.example.com", false}, // 非泛域 pattern 不是通配
		{"*", "x.example.com", false},                 // 空 zone 无效
		{"*.example.com", "SUB.EXAMPLE.COM", true},    // 大小写不敏感
	}
	for _, c := range cases {
		require.Equal(t, c.want, wildcardCovers(c.pattern, c.domain),
			"wildcardCovers(%q, %q)", c.pattern, c.domain)
	}
}

func TestDomainsCovered(t *testing.T) {
	require.True(t, domainsCovered([]string{"*.example.com"}, []string{"*.example.com"})) // 精确相等
	require.True(t, domainsCovered([]string{"a.com", "*.example.com"}, []string{"sub.example.com", "a.com"}))
	require.False(t, domainsCovered([]string{"*.example.com"}, []string{"example.com"}))
	require.False(t, domainsCovered([]string{"*.example.com"}, []string{"sub.example.com", "other.com"}))
	require.False(t, domainsCovered([]string{"*.example.com"}, nil)) // 空请求不成立
}

func TestFindReusableEntry(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()
	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, AllowSubdomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, role)

	// 同 account 其他 role 签发的泛域名条目（fresh，Users=0 模拟异步产物）
	wildRole := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	key := putFreshCacheEntry(t, b, ctx, storage, wildRole, []string{"*.example.com"})
	// putFreshCacheEntry 不写 Role——手工补上（模拟真实签发后的条目）
	require.NoError(t, b.cacheUpdate(ctx, storage, key, func(e *cacheEntry) *cacheEntry {
		e.Role = "wild"
		return e
	}))

	// 命中：同 account 跨 role 的单层覆盖
	entry, k, err := b.findReusableEntry(ctx, storage, role, []string{"sub.example.com"})
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, key, k)

	// 裸域不覆盖 → 未命中
	entry, _, err = b.findReusableEntry(ctx, storage, role, []string{"example.com"})
	require.NoError(t, err)
	require.Nil(t, entry)

	// 多级子域不覆盖 → 未命中
	entry, _, err = b.findReusableEntry(ctx, storage, role, []string{"a.b.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry)

	// Role=="" 的旧条目跳过
	require.NoError(t, b.cacheUpdate(ctx, storage, key, func(e *cacheEntry) *cacheEntry {
		e.Role = ""
		return e
	}))
	entry, _, err = b.findReusableEntry(ctx, storage, role, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry)
}

func TestFindReusableEntryGuards(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()
	role := &roleEntry{Account: "le", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, AllowSubdomains: true, CacheForRatio: 70}
	putRoleFixture(t, ctx, storage, role)

	// 跨 account 不复用
	otherAcct := &roleEntry{Account: "other", AllowedDomains: []string{"example.com"},
		AllowBareDomains: true, CacheForRatio: 70}
	key := putFreshCacheEntry(t, b, ctx, storage, otherAcct, []string{"*.example.com"})
	require.NoError(t, b.cacheUpdate(ctx, storage, key, func(e *cacheEntry) *cacheEntry {
		e.Role = "wild"
		return e
	}))
	entry, _, err := b.findReusableEntry(ctx, storage, role, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry, "跨 account 不得复用")

	// 到期条目不复用
	staleKey := putFreshCacheEntry(t, b, ctx, storage, role, []string{"sub.example.com"})
	require.NoError(t, b.cacheUpdate(ctx, storage, staleKey, func(e *cacheEntry) *cacheEntry {
		base := time.Now().UTC()
		e.Role = "wild"
		e.CertificatePEM = selfSignedCertFor(t, base.Add(-100*time.Hour), base.Add(-time.Hour)) // 已过期
		return e
	}))
	entry, _, err = b.findReusableEntry(ctx, storage, role, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry, "到期条目不得复用")

	// disable_cache / disable_cert_reuse 直接短路
	dc := &roleEntry{Account: "le", DisableCache: true, CacheForRatio: 70}
	entry, _, err = b.findReusableEntry(ctx, storage, dc, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry, "disable_cache 不得复用")

	dr := &roleEntry{Account: "le", DisableCertReuse: true, CacheForRatio: 70}
	entry, _, err = b.findReusableEntry(ctx, storage, dr, []string{"sub.example.com"})
	require.NoError(t, err)
	require.Nil(t, entry, "disable_cert_reuse 不得复用")
}
