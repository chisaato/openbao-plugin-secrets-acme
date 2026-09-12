package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	StorageKeyAccounts     = "accounts/"
	StorageKeyRoles        = "roles/"
	StorageKeyDNSProviders = "dns-providers/"
	StorageKeyJobs         = "jobs/"
	StorageKeyCache        = "cache/"
)

// CredentialsRef 描述一处 KV 凭据引用。Keys 左键为适配层所需的 lego
// 环境变量名，右值为用户 KV 数据中的实际键名；缺省时回退同名查找。
// mapstructure tag 供路径层 FieldData(map) WeakDecode 使用（如 kv_version）。
type CredentialsRef struct {
	Mount     string            `json:"mount" mapstructure:"mount"`
	Path      string            `json:"path" mapstructure:"path"`
	KVVersion string            `json:"kv_version" mapstructure:"kv_version"`
	Version   int               `json:"version" mapstructure:"version"`
	Keys      map[string]string `json:"keys" mapstructure:"keys"`
}

func (r *CredentialsRef) KVVersionNormalized() string {
	if r.KVVersion == "1" {
		return "1"
	}
	return "2"
}

// DNSProviderRef 引用一个 dns-providers/{name} 条目；Zones 为空表示兜底。
type DNSProviderRef struct {
	Name  string   `json:"name"`
	Zones []string `json:"zones,omitempty"`
}

// AccountEntry 是 accounts/{name} 的持久化记录。
type AccountEntry struct {
	Name             string           `json:"name"`
	ServerURL        string           `json:"server_url"`
	Contact          string           `json:"contact"`
	TOSAgreed        bool             `json:"terms_of_service_agreed"`
	KeyType          string           `json:"key_type"`
	PrivateKeyPEM    string           `json:"private_key_pem"`
	RegistrationJSON string           `json:"registration_json"`
	InsecureTLS      bool             `json:"insecure_tls"`
	DNSProviders     []DNSProviderRef `json:"dns_providers"`
}

// RoleEntry：签发策略（域名白名单、缓存策略、KV 输出目标）。
type RoleEntry struct {
	Account          string   `json:"account"`
	AllowedDomains   []string `json:"allowed_domains"`
	AllowBareDomains bool     `json:"allow_bare_domains"`
	AllowSubdomains  bool     `json:"allow_subdomains"`
	AllowAnyName     bool     `json:"allow_any_name"`
	DisableCache     bool     `json:"disable_cache"`
	DisableCertReuse bool     `json:"disable_cert_reuse"`
	CacheForRatio    int      `json:"cache_for_ratio"`
	OutputKVMount    string   `json:"output_kv_mount"`
}

// DNSProviderEntry 是 dns-providers/{name} 的持久化记录。
type DNSProviderEntry struct {
	Type                 string          `json:"type"`
	CredentialsRef       *CredentialsRef `json:"credentials_ref,omitempty"`
	PropagationTimeout   time.Duration   `json:"propagation_timeout"`
	PollingInterval      time.Duration   `json:"polling_interval"`
	SkipPropagationCheck bool            `json:"skip_propagation_check"`
	PropagationWait      int             `json:"propagation_wait"`
	Resolvers            []string        `json:"resolvers,omitempty"`
}

// JobEntry：异步签发任务。
type JobEntry struct {
	ID                   string               `json:"id"`
	Role                 string               `json:"role"`
	Account              string               `json:"account"`
	CN                   string               `json:"common_name"`
	AltNames             []string             `json:"alt_names"`
	Domains              []string             `json:"domains"`
	CacheKey             string               `json:"cache_key"`
	Status               api.JobStatus        `json:"status"`
	Error                string               `json:"error,omitempty"`
	CreatedAt            time.Time            `json:"created_at"`
	UpdatedAt            time.Time            `json:"updated_at"`
	Cert                 *api.JobCertSnapshot `json:"cert,omitempty"`
	SkipPropagationCheck *bool                `json:"skip_propagation_check,omitempty"`
	PropagationWait      *int                 `json:"propagation_wait,omitempty"`
	Resolvers            []string             `json:"resolvers,omitempty"`
}

// CacheEntry：共享证书条目；Users 为引用计数。
type CacheEntry struct {
	Users                int      `json:"users"`
	Account              string   `json:"account"`
	CN                   string   `json:"cn"`
	Domains              []string `json:"domains"`
	CertURL              string   `json:"cert_url"`
	CertStableURL        string   `json:"cert_stable_url"`
	PrivateKeyPEM        string   `json:"private_key_pem"`
	CertificatePEM       string   `json:"certificate_pem"`
	IssuerCertificatePEM string   `json:"issuer_certificate_pem"`
	Role                 string   `json:"role,omitempty"`
	// OutputKVMount：上次成功写入的 KV mount。空=尚未成功写过。
	OutputKVMount string `json:"output_kv_mount,omitempty"`
	// OutputKVPath：上次成功写入的完整 KV 数据路径（mount + "/" + certs/{certID}），
	// 如 "secret/certs/abc123"。语义与 OutputKVMount 一致：最后成功写入的位置；
	// BestEffort 冲突/读失败跳过时保持旧值不更新。空=旧条目（展示层回退拼接）。
	OutputKVPath string `json:"output_kv_path,omitempty"`
	// OutputKVStatus：投影状态 written/skipped_conflict/skipped_error；空=未配置
	// 同步或旧条目（零值回退）。
	OutputKVStatus string `json:"output_kv_status,omitempty"`
}

// --- Account CRUD ---

func GetAccount(ctx context.Context, s logical.Storage, name string) (*AccountEntry, error) {
	item, err := s.Get(ctx, StorageKeyAccounts+name)
	if err != nil || item == nil {
		return nil, err
	}
	var entry AccountEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func PutAccount(ctx context.Context, s logical.Storage, name string, entry *AccountEntry) error {
	item, err := logical.StorageEntryJSON(StorageKeyAccounts+name, entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, item)
}

func DeleteAccount(ctx context.Context, s logical.Storage, name string) error {
	return s.Delete(ctx, StorageKeyAccounts+name)
}

func ListAccounts(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, StorageKeyAccounts)
}

// --- Role CRUD ---

func GetRole(ctx context.Context, s logical.Storage, name string) (*RoleEntry, error) {
	item, err := s.Get(ctx, StorageKeyRoles+name)
	if err != nil || item == nil {
		return nil, err
	}
	var role RoleEntry
	if err := item.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func PutRole(ctx context.Context, s logical.Storage, name string, role *RoleEntry) error {
	item, err := logical.StorageEntryJSON(StorageKeyRoles+name, role)
	if err != nil {
		return err
	}
	return s.Put(ctx, item)
}

func DeleteRole(ctx context.Context, s logical.Storage, name string) error {
	return s.Delete(ctx, StorageKeyRoles+name)
}

func ListRoles(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, StorageKeyRoles)
}

// --- DNS Provider CRUD ---

func GetDNSProvider(ctx context.Context, s logical.Storage, name string) (*DNSProviderEntry, error) {
	item, err := s.Get(ctx, StorageKeyDNSProviders+name)
	if err != nil || item == nil {
		return nil, err
	}
	var entry DNSProviderEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func PutDNSProvider(ctx context.Context, s logical.Storage, name string, entry *DNSProviderEntry) error {
	item, err := logical.StorageEntryJSON(StorageKeyDNSProviders+name, entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, item)
}

func DeleteDNSProvider(ctx context.Context, s logical.Storage, name string) error {
	return s.Delete(ctx, StorageKeyDNSProviders+name)
}

func ListDNSProviders(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, StorageKeyDNSProviders)
}

// --- Job CRUD ---

func GetJob(ctx context.Context, s logical.Storage, id string) (*JobEntry, error) {
	item, err := s.Get(ctx, StorageKeyJobs+id)
	if err != nil || item == nil {
		return nil, err
	}
	var entry JobEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func PutJob(ctx context.Context, s logical.Storage, id string, job *JobEntry) error {
	item, err := logical.StorageEntryJSON(StorageKeyJobs+id, job)
	if err != nil {
		return err
	}
	return s.Put(ctx, item)
}

func DeleteJob(ctx context.Context, s logical.Storage, id string) error {
	return s.Delete(ctx, StorageKeyJobs+id)
}

func ListJobs(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, StorageKeyJobs)
}

// --- Cache CRUD ---

func GetCache(ctx context.Context, s logical.Storage, key string) (*CacheEntry, error) {
	item, err := s.Get(ctx, StorageKeyCache+key)
	if err != nil || item == nil {
		return nil, err
	}
	var entry CacheEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func PutCache(ctx context.Context, s logical.Storage, key string, entry *CacheEntry) error {
	item, err := logical.StorageEntryJSON(StorageKeyCache+key, entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, item)
}

func DeleteCache(ctx context.Context, s logical.Storage, key string) error {
	return s.Delete(ctx, StorageKeyCache+key)
}

func ListCache(ctx context.Context, s logical.Storage) ([]string, error) {
	return s.List(ctx, StorageKeyCache)
}

// FormatStorageError 辅助统一包装存储错误
func FormatStorageError(op, key string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("storage %s [%s] failed: %w", op, key, err)
}
