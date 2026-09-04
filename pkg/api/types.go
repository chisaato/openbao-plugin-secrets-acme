package api

// JobStatus 描述异步签发任务的生命周期状态。
type JobStatus string

const (
	JobPending    JobStatus = "pending"
	JobProcessing JobStatus = "processing"
	JobCompleted  JobStatus = "completed"
	JobFailed     JobStatus = "failed"
)

// DNSProviderRef 引用一个 dns-providers/{name} 条目；Zones 为空表示兜底。
type DNSProviderRef struct {
	Name  string   `json:"name" mapstructure:"name"`
	Zones []string `json:"zones,omitempty" mapstructure:"zones"`
}

// CredentialsRef 是凭据在 OpenBao 中的存储位置引用。
type CredentialsRef struct {
	Mount string `json:"mount" mapstructure:"mount"`
	Path  string `json:"path" mapstructure:"path"`
}

// JobCertSnapshot 是 Job 状态为 completed 时的证书快照。
type JobCertSnapshot struct {
	CertificatePEM string `json:"certificate,omitempty" mapstructure:"certificate"`
	PrivateKeyPEM  string `json:"private_key,omitempty" mapstructure:"private_key"`
	IssuerCertPEM  string `json:"issuer_cert,omitempty" mapstructure:"issuer_cert"`
	CertURL        string `json:"url,omitempty" mapstructure:"url"`
	CertStableURL  string `json:"cert_stable_url,omitempty" mapstructure:"cert_stable_url"`
	NotBefore      string `json:"not_before,omitempty" mapstructure:"not_before"`
	NotAfter       string `json:"not_after,omitempty" mapstructure:"not_after"`
	OutputPath     string `json:"output_path,omitempty" mapstructure:"output_path"`
}
