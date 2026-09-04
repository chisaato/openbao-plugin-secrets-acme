package acme

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// wildcardCovers：pattern 形如 *.zone 时仅覆盖单层标签（label 非空且不含点）。
// 裸域与多级子域不被泛域名覆盖（spec §5.2 正确性边界）。大小写不敏感。
func wildcardCovers(pattern, domain string) bool {
	zone, ok := strings.CutPrefix(strings.ToLower(pattern), "*.")
	if !ok || zone == "" {
		return false
	}
	label, rest, found := strings.Cut(strings.ToLower(domain), ".")
	return found && rest == zone && label != ""
}

// domainCovered：精确相等，或单层通配覆盖。
func domainCovered(entryDomain, requestDomain string) bool {
	return strings.EqualFold(entryDomain, requestDomain) || wildcardCovers(entryDomain, requestDomain)
}

// domainsCovered：单个条目的域名集合须覆盖请求的全部域名（spec §5.2）。
func domainsCovered(entryDomains, requestDomains []string) bool {
	if len(requestDomains) == 0 {
		return false
	}
	for _, d := range requestDomains {
		ok := false
		for _, e := range entryDomains {
			if domainCovered(e, d) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// findReusableEntry：account 级覆盖复用扫描（spec §5）。过滤链：
// role 开关（disable_cache/disable_cert_reuse）→ 条目来源（Role 非空、
// 同 account）→ 新鲜度（按请求 role 的 CacheForRatio）→ 全域名覆盖。
// 未命中返回 (nil, "", nil)。
func (b *backend) findReusableEntry(ctx context.Context, s logical.Storage, role *roleEntry, domains []string) (*cacheEntry, string, error) {
	if role.DisableCache || role.DisableCertReuse {
		return nil, "", nil
	}
	keys, err := s.List(ctx, storageKeyCache)
	if err != nil {
		return nil, "", err
	}
	for _, k := range keys {
		item, err := s.Get(ctx, storageKeyCache+k)
		if err != nil {
			return nil, "", err
		}
		if item == nil {
			continue
		}
		var entry cacheEntry
		if err := item.DecodeJSON(&entry); err != nil {
			return nil, "", err
		}
		if entry.Role == "" || entry.Account != role.Account {
			continue
		}
		if certNeedsRenewal(entry.CertificatePEM, role.CacheForRatio) {
			continue
		}
		if !domainsCovered(entry.Domains, domains) {
			continue
		}
		return &entry, k, nil
	}
	return nil, "", nil
}

// reuseKVPath：复用响应的 output_path 指向签发时真实写入的位置。
// 跨 role 复用时按签发 role 的 output_kv_mount 解析；签发 role 已删除或
// 未配 KV 输出则省略 output_path（指向不存在的路径会误导调用方）。
func (b *backend) reuseKVPath(ctx context.Context, s logical.Storage, roleName string, role *roleEntry, entry *cacheEntry) string {
	if entry.Role != "" && entry.Role != roleName {
		issuer, err := b.getRole(ctx, s, entry.Role)
		if err != nil || issuer == nil || issuer.OutputKVMount == "" {
			return ""
		}
		return outputKVPath(entry.Role, entry.CN)
	}
	if role.OutputKVMount == "" {
		return ""
	}
	return outputKVPath(roleName, entry.CN)
}
