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

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyCache = storage.StorageKeyCache

// cacheEntry 兼容 storage.CacheEntry
type cacheEntry = storage.CacheEntry

// cacheKey 只由真正决定证书输出的要素派生:CA 环境(ServerURL)、ACME 账号
// 身份(账号私钥)、CSR 公钥类型(KeyType)与域名集合。role 白名单、缓存
// 策略、KV 输出配置等客户端策略不参与——role/account 的非签发字段变更或
// account 改名都不再使 Cert ID 漂移。
// 各字段间以 \x00 分隔,避免字符串拼接产生歧义(如跨字段内容错位拼合)。
func cacheKey(account *storage.AccountEntry, domains []string) string {
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(account.ServerURL + "\x00" + account.KeyType + "\x00" + account.PrivateKeyPEM + "\x00" + strings.Join(sorted, ",")))
	return hex.EncodeToString(sum[:])
}

func (b *backend) cacheGet(ctx context.Context, s logical.Storage, key string) (*cacheEntry, error) {
	b.cacheMu.RLock()
	defer b.cacheMu.RUnlock()
	return storage.GetCache(ctx, s, key)
}

func (b *backend) cachePut(ctx context.Context, s logical.Storage, key string, entry *cacheEntry) error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	return storage.PutCache(ctx, s, key, entry)
}

func (b *backend) cacheDelete(ctx context.Context, s logical.Storage, key string) error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	return storage.DeleteCache(ctx, s, key)
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

// waiterRefAdd：singleflight 等待者为其 lease 补充引用计数。doIssue 写入的
// 初始 Users=1 归属领导者对应的 lease；等待者共享领导者的响应后同样会各建
// 一个 lease，须在单写临界区补自增，维持不变式 Users == 持有该条目的 lease
// 数。条目此刻消失（极端竞争）返回错误，由调用方保守处理。
func (b *backend) waiterRefAdd(ctx context.Context, s logical.Storage, key string) error {
	return b.cacheUpdate(ctx, s, key, func(e *cacheEntry) *cacheEntry {
		e.Users++
		return e
	})
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
