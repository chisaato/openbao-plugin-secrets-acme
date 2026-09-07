package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainFilterAndMatch(t *testing.T) {
	// 1. 测试 MatchDomain
	assert.True(t, MatchDomain("example.com", "example.com"))
	assert.True(t, MatchDomain("EXAMPLE.COM", "example.com"))
	assert.True(t, MatchDomain("*.example.com", "sub.example.com"))
	assert.True(t, MatchDomain("*.example.com", "api.example.com"))
	// 泛域名不应跨多级匹配
	assert.False(t, MatchDomain("*.example.com", "a.b.example.com"))
	assert.False(t, MatchDomain("*.example.com", "example.com"))

	// 2. 测试 CertCoversAllDomains
	certDoms := []string{"example.com", "*.example.com"}
	assert.True(t, CertCoversAllDomains(certDoms, []string{"example.com"}))
	assert.True(t, CertCoversAllDomains(certDoms, []string{"app.example.com"}))
	assert.True(t, CertCoversAllDomains(certDoms, []string{"example.com", "app.example.com"}))
	assert.False(t, CertCoversAllDomains(certDoms, []string{"example.com", "other.org"}))

	// 3. 测试 FilterCertsByDomains
	certs := []CertSummary{
		{
			ID:      "id-1",
			Domains: []string{"example.com"},
		},
		{
			ID:      "id-2",
			Domains: []string{"example.com", "*.example.com"},
		},
		{
			ID:      "id-3",
			Domains: []string{"google.com"},
		},
	}

	// 过滤 sub.example.com
	filtered := FilterCertsByDomains(certs, []string{"sub.example.com"}, false)
	assert.Len(t, filtered, 1)
	assert.Equal(t, "id-2", filtered[0].ID)

	// 过滤 example.com
	filteredExample := FilterCertsByDomains(certs, []string{"example.com"}, false)
	assert.Len(t, filteredExample, 2)
}
