package api

import (
	"time"
)

// DNSProvider 是 dns-providers/{name} 的配置与响应实体。
type DNSProvider struct {
	Type                 string          `json:"type" mapstructure:"type"`
	CredentialsRef       *CredentialsRef `json:"credentials_ref,omitempty" mapstructure:"credentials_ref"`
	PropagationTimeout   time.Duration   `json:"propagation_timeout" mapstructure:"propagation_timeout"`
	PollingInterval      time.Duration   `json:"polling_interval" mapstructure:"polling_interval"`
	SkipPropagationCheck bool            `json:"skip_propagation_check" mapstructure:"skip_propagation_check"`
	PropagationWait      int             `json:"propagation_wait" mapstructure:"propagation_wait"`
}

// Account 是 accounts/{name} 的配置与响应实体。
type Account struct {
	Name             string           `json:"name,omitempty" mapstructure:"name"`
	ServerURL        string           `json:"server_url" mapstructure:"server_url"`
	Contact          string           `json:"contact" mapstructure:"contact"`
	TOSAgreed        bool             `json:"terms_of_service_agreed" mapstructure:"terms_of_service_agreed"`
	KeyType          string           `json:"key_type,omitempty" mapstructure:"key_type"`
	PrivateKeyPEM    string           `json:"private_key_pem,omitempty" mapstructure:"private_key_pem"`
	RegistrationJSON string           `json:"registration_json,omitempty" mapstructure:"registration_json"`
	InsecureTLS      bool             `json:"insecure_tls" mapstructure:"insecure_tls"`
	DNSProviders     []DNSProviderRef `json:"dns_providers" mapstructure:"dns_providers"`
	Status           string           `json:"status,omitempty" mapstructure:"status"`
}

// Role 是 roles/{name} 的配置与响应实体。
type Role struct {
	Account          string   `json:"account" mapstructure:"account"`
	AllowedDomains   []string `json:"allowed_domains" mapstructure:"allowed_domains"`
	AllowBareDomains bool     `json:"allow_bare_domains" mapstructure:"allow_bare_domains"`
	AllowSubdomains  bool     `json:"allow_subdomains" mapstructure:"allow_subdomains"`
	AllowAnyName     bool     `json:"allow_any_name" mapstructure:"allow_any_name"`
	DisableCache     bool     `json:"disable_cache" mapstructure:"disable_cache"`
	DisableCertReuse bool     `json:"disable_cert_reuse" mapstructure:"disable_cert_reuse"`
	CacheForRatio    int      `json:"cache_for_ratio" mapstructure:"cache_for_ratio"`
	OutputKVMount    string   `json:"output_kv_mount" mapstructure:"output_kv_mount"`
}

// IssueOptions 是向 certs/{role} 发起签发请求的参数。
type IssueOptions struct {
	CommonName string   `json:"common_name" mapstructure:"common_name"`
	AltNames   []string `json:"alt_names,omitempty" mapstructure:"alt_names"`
	Sync       bool     `json:"sync,omitempty" mapstructure:"sync"`
}

// IssueResponse 包含 POST certs/{role} 返回的结果（异步 Job 模式或同步模式）。
type IssueResponse struct {
	// 异步模式返回
	JobID      string   `json:"job_id,omitempty" mapstructure:"job_id"`
	CommonName string   `json:"common_name,omitempty" mapstructure:"common_name"`
	Domains    []string `json:"domains,omitempty" mapstructure:"domains"`
	CreatedAt  string   `json:"created_at,omitempty" mapstructure:"created_at"`
	PollPath   string   `json:"poll_path,omitempty" mapstructure:"poll_path"`

	// 同步模式返回
	CertificatePEM string `json:"certificate,omitempty" mapstructure:"certificate"`
	PrivateKeyPEM  string `json:"private_key,omitempty" mapstructure:"private_key"`
	IssuerCertPEM  string `json:"issuer_cert,omitempty" mapstructure:"issuer_cert"`
	CertURL        string `json:"url,omitempty" mapstructure:"url"`
	CertStableURL  string `json:"cert_stable_url,omitempty" mapstructure:"cert_stable_url"`
	NotBefore      string `json:"not_before,omitempty" mapstructure:"not_before"`
	NotAfter       string `json:"not_after,omitempty" mapstructure:"not_after"`
	OutputPath     string `json:"output_path,omitempty" mapstructure:"output_path"`
	Reused         bool   `json:"reused,omitempty" mapstructure:"reused"`
	Status         string `json:"status,omitempty" mapstructure:"status"`
	Error          string `json:"error,omitempty" mapstructure:"error"`
}

// JobDetail 是 GET jobs/{id} 返回的完整任务信息。
type JobDetail struct {
	ID         string           `json:"id" mapstructure:"id"`
	Role       string           `json:"role" mapstructure:"role"`
	Account    string           `json:"account" mapstructure:"account"`
	CommonName string           `json:"common_name" mapstructure:"common_name"`
	AltNames   []string         `json:"alt_names" mapstructure:"alt_names"`
	Domains    []string         `json:"domains" mapstructure:"domains"`
	CacheKey   string           `json:"cache_key" mapstructure:"cache_key"`
	Status     JobStatus        `json:"status" mapstructure:"status"`
	Error      string           `json:"error,omitempty" mapstructure:"error"`
	CreatedAt  string           `json:"created_at" mapstructure:"created_at"`
	UpdatedAt  string           `json:"updated_at" mapstructure:"updated_at"`
	Cert       *JobCertSnapshot `json:"cert,omitempty" mapstructure:"cert"`
}
