package acme

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyCache = "cache/"

// cacheEntry：共享证书条目；Users 为引用计数（每个 lease 持有一个引用）。
type cacheEntry struct {
	Users                int      `json:"users"`
	Account              string   `json:"account"`
	CN                   string   `json:"cn"`
	Domains              []string `json:"domains"`
	CertURL              string   `json:"cert_url"`
	CertStableURL        string   `json:"cert_stable_url"`
	PrivateKeyPEM        string   `json:"private_key_pem"`
	CertificatePEM       string   `json:"certificate_pem"`
	IssuerCertificatePEM string   `json:"issuer_certificate_pem"`
}

// cacheKey：sha256(roleJSON + 排序后 domains)，域名顺序无关。
func cacheKey(role *roleEntry, domains []string) string {
	roleJSON, _ := json.Marshal(role)
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	sum := sha256.Sum256(append(roleJSON, []byte(strings.Join(sorted, ","))...))
	return hex.EncodeToString(sum[:])
}

func (b *backend) cacheGet(ctx context.Context, s logical.Storage, key string) (*cacheEntry, error) {
	b.cacheMu.RLock()
	defer b.cacheMu.RUnlock()
	item, err := s.Get(ctx, storageKeyCache+key)
	if err != nil || item == nil {
		return nil, err
	}
	var entry cacheEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (b *backend) cachePut(ctx context.Context, s logical.Storage, key string, entry *cacheEntry) error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, &logical.StorageEntry{Key: storageKeyCache + key, Value: raw})
}

func (b *backend) cacheDelete(ctx context.Context, s logical.Storage, key string) error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	return s.Delete(ctx, storageKeyCache+key)
}

// cacheUpdate 在单个写临界区内完成 get→变更→put，保证并发调用者的读改写
// 原子性（如命中路径的 Users 引用计数自增）。fn 返回 nil 表示删除条目；
// 条目在临界区内已不存在（如被并发删除）时返回错误，由调用方决定重试。
func (b *backend) cacheUpdate(ctx context.Context, s logical.Storage, key string, fn func(*cacheEntry) *cacheEntry) error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	item, err := s.Get(ctx, storageKeyCache+key)
	if err != nil {
		return err
	}
	if item == nil {
		return fmt.Errorf("cache entry %q 已不存在", key)
	}
	var entry cacheEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return err
	}
	updated := fn(&entry)
	if updated == nil {
		return s.Delete(ctx, storageKeyCache+key)
	}
	raw, err := json.Marshal(updated)
	if err != nil {
		return err
	}
	return s.Put(ctx, &logical.StorageEntry{Key: storageKeyCache + key, Value: raw})
}

func (b *backend) cacheCount(ctx context.Context, s logical.Storage) (int, error) {
	b.cacheMu.RLock()
	defer b.cacheMu.RUnlock()
	keys, err := s.List(ctx, storageKeyCache)
	return len(keys), err
}

func (b *backend) cacheClear(ctx context.Context, s logical.Storage) (int, error) {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	keys, err := s.List(ctx, storageKeyCache)
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if err := s.Delete(ctx, storageKeyCache+k); err != nil {
			return 0, err
		}
	}
	return len(keys), nil
}

// certNeedsRenewal：剩余寿命 < 总寿命×ratio% → true；解析失败保守返回 true。
func certNeedsRenewal(certPEM string, ratio int) bool {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	total := cert.NotAfter.Sub(cert.NotBefore)
	remaining := time.Until(cert.NotAfter)
	return remaining < total*time.Duration(ratio)/100
}
