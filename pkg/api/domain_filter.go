package api

import (
	"strings"
)

// MatchDomain 判断 domain 是否匹配 pattern (支持泛域名通配符，如 *.example.com 匹配 sub.example.com)。
func MatchDomain(pattern, domain string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	d := strings.ToLower(strings.TrimSpace(domain))
	if p == d {
		return true
	}
	if strings.HasPrefix(p, "*.") {
		base := p[2:]
		// 泛域名仅匹配单层子域名
		if strings.HasSuffix(d, "."+base) {
			prefix := strings.TrimSuffix(d, "."+base)
			if !strings.Contains(prefix, ".") {
				return true
			}
		}
	}
	return false
}

// CertCoversDomain 检查证书包含的域名列表是否能覆盖指定的目标域名。
func CertCoversDomain(certDomains []string, targetDomain string) bool {
	for _, cd := range certDomains {
		if MatchDomain(cd, targetDomain) {
			return true
		}
	}
	return false
}

// CertCoversAllDomains 检查证书域名列表是否覆盖目标域名列表中的全部域名。
func CertCoversAllDomains(certDomains []string, targetDomains []string) bool {
	if len(targetDomains) == 0 {
		return false
	}
	for _, td := range targetDomains {
		if !CertCoversDomain(certDomains, td) {
			return false
		}
	}
	return true
}

// FilterCertsByDomains 按给定的域名列表过滤证书列表：
// 只要证书能够匹配目标域名中的任意一个（或全部覆盖），就保留。
func FilterCertsByDomains(certs []CertSummary, filterDomains []string, matchAll bool) []CertSummary {
	if len(filterDomains) == 0 {
		return certs
	}
	var out []CertSummary
	for _, c := range certs {
		if matchAll {
			if CertCoversAllDomains(c.Domains, filterDomains) {
				out = append(out, c)
			}
		} else {
			matched := false
			for _, fd := range filterDomains {
				if CertCoversDomain(c.Domains, fd) {
					matched = true
					break
				}
			}
			if matched {
				out = append(out, c)
			}
		}
	}
	return out
}
