package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/go-viper/mapstructure/v2"
	baoapi "github.com/openbao/openbao/api/v2"
)

// Client 封装与 OpenBao ACME 插件的交互。
type Client struct {
	bao   *baoapi.Client
	mount string
}

// Config 是 Client 的配置项。
type Config struct {
	Address string
	Token   string
	Mount   string // 默认 "acme"
}

// NewClient 创建一个新的 Client。
func NewClient(cfg Config) (*Client, error) {
	addr := cfg.Address
	if addr == "" {
		addr = os.Getenv("BAO_ADDR")
		if addr == "" {
			addr = os.Getenv("VAULT_ADDR")
		}
		if addr == "" {
			addr = "http://127.0.0.1:8200"
		}
	}

	token := cfg.Token
	if token == "" {
		token = os.Getenv("BAO_TOKEN")
		if token == "" {
			token = os.Getenv("VAULT_TOKEN")
		}
	}

	mount := cfg.Mount
	if mount == "" {
		mount = os.Getenv("ACME_MOUNT")
		if mount == "" {
			mount = "acme"
		}
	}
	mount = strings.Trim(mount, "/")

	baoConfig := baoapi.DefaultConfig()
	baoConfig.Address = addr

	baoClient, err := baoapi.NewClient(baoConfig)
	if err != nil {
		return nil, fmt.Errorf("init openbao client: %w", err)
	}

	if token != "" {
		baoClient.SetToken(token)
	}

	return &Client{
		bao:   baoClient,
		mount: mount,
	}, nil
}

// RawClient 返回底层 OpenBao API 客户端。
func (c *Client) RawClient() *baoapi.Client {
	return c.bao
}

// p 拼接插件相对路径为绝对逻辑路径。
func (c *Client) p(subpath string) string {
	return path.Join(c.mount, strings.TrimPrefix(subpath, "/"))
}

// durationHook 兼容 json.Number、string、int64 到 time.Duration 的安全解析。
func durationHook() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf(time.Duration(0)) {
			return data, nil
		}
		switch v := data.(type) {
		case string:
			return time.ParseDuration(v)
		case json.Number:
			i, err := v.Int64()
			if err == nil {
				return time.Duration(i), nil
			}
			fl, err := v.Float64()
			if err == nil {
				return time.Duration(fl), nil
			}
			return time.ParseDuration(v.String())
		case int64:
			return time.Duration(v), nil
		case int:
			return time.Duration(v), nil
		case float64:
			return time.Duration(v), nil
		}
		return data, nil
	}
}

// decodeData 将 OpenBao Secret.Data 解码到目标结构体中。
func decodeData(data map[string]any, target any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           target,
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			durationHook(),
			mapstructure.StringToTimeDurationHookFunc(),
		),
	})
	if err != nil {
		return err
	}
	return decoder.Decode(data)
}

// ---- Accounts ----

func (c *Client) RegisterAccount(ctx context.Context, name string, account api.Account) (*api.Account, error) {
	data := map[string]any{
		"server_url":               account.ServerURL,
		"contact":                  account.Contact,
		"terms_of_service_agreed": account.TOSAgreed,
		"insecure_tls":             account.InsecureTLS,
	}
	if account.KeyType != "" {
		data["key_type"] = account.KeyType
	}
	if len(account.DNSProviders) > 0 {
		var providers []map[string]any
		for _, p := range account.DNSProviders {
			m := map[string]any{"name": p.Name}
			if len(p.Zones) > 0 {
				m["zones"] = p.Zones
			}
			providers = append(providers, m)
		}
		data["dns_providers"] = providers
	}

	sec, err := c.bao.Logical().WriteWithContext(ctx, c.p("accounts/"+name), data)
	if err != nil {
		return nil, err
	}
	res := &api.Account{Name: name}
	if sec != nil && sec.Data != nil {
		if err := decodeData(sec.Data, res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (c *Client) GetAccount(ctx context.Context, name string) (*api.Account, error) {
	sec, err := c.bao.Logical().ReadWithContext(ctx, c.p("accounts/"+name))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("account %q not found", name)
	}
	res := &api.Account{Name: name}
	if err := decodeData(sec.Data, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *Client) ListAccounts(ctx context.Context) ([]string, error) {
	sec, err := c.bao.Logical().ListWithContext(ctx, c.p("accounts"))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return []string{}, nil
	}
	keys, ok := sec.Data["keys"].([]any)
	if !ok {
		return []string{}, nil
	}
	var res []string
	for _, k := range keys {
		if s, ok := k.(string); ok {
			res = append(res, strings.TrimSuffix(s, "/"))
		}
	}
	return res, nil
}

func (c *Client) DeactivateAccount(ctx context.Context, name string) error {
	_, err := c.bao.Logical().DeleteWithContext(ctx, c.p("accounts/"+name))
	return err
}

// ---- DNS Providers ----

func (c *Client) SetDNSProvider(ctx context.Context, name string, p api.DNSProvider) error {
	data := map[string]any{
		"type": p.Type,
	}
	if p.CredentialsRef != nil {
		data["credentials_ref"] = map[string]any{
			"mount": p.CredentialsRef.Mount,
			"path":  p.CredentialsRef.Path,
		}
	}
	if p.PropagationTimeout > 0 {
		data["propagation_timeout"] = p.PropagationTimeout.String()
	}
	if p.PollingInterval > 0 {
		data["polling_interval"] = p.PollingInterval.String()
	}
	if p.SkipPropagationCheck {
		data["skip_propagation_check"] = p.SkipPropagationCheck
	}
	if p.PropagationWait > 0 {
		data["propagation_wait"] = p.PropagationWait
	}
	if len(p.Resolvers) > 0 {
		data["resolvers"] = p.Resolvers
	}

	_, err := c.bao.Logical().WriteWithContext(ctx, c.p("dns-providers/"+name), data)
	return err
}

func (c *Client) GetDNSProvider(ctx context.Context, name string) (*api.DNSProvider, error) {
	sec, err := c.bao.Logical().ReadWithContext(ctx, c.p("dns-providers/"+name))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("dns-provider %q not found", name)
	}
	res := &api.DNSProvider{}
	if err := decodeData(sec.Data, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *Client) ListDNSProviders(ctx context.Context) ([]string, error) {
	sec, err := c.bao.Logical().ListWithContext(ctx, c.p("dns-providers"))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return []string{}, nil
	}
	keys, ok := sec.Data["keys"].([]any)
	if !ok {
		return []string{}, nil
	}
	var res []string
	for _, k := range keys {
		if s, ok := k.(string); ok {
			res = append(res, strings.TrimSuffix(s, "/"))
		}
	}
	return res, nil
}

func (c *Client) DeleteDNSProvider(ctx context.Context, name string) error {
	_, err := c.bao.Logical().DeleteWithContext(ctx, c.p("dns-providers/"+name))
	return err
}

// ---- Roles ----

func (c *Client) SetRole(ctx context.Context, name string, r api.Role) error {
	data := map[string]any{
		"account":            r.Account,
		"allowed_domains":    r.AllowedDomains,
		"allow_bare_domains": r.AllowBareDomains,
		"allow_subdomains":   r.AllowSubdomains,
		"allow_any_name":     r.AllowAnyName,
		"disable_cache":      r.DisableCache,
		"disable_cert_reuse": r.DisableCertReuse,
		"cache_for_ratio":    r.CacheForRatio,
		"output_kv_mount":    r.OutputKVMount,
	}
	_, err := c.bao.Logical().WriteWithContext(ctx, c.p("roles/"+name), data)
	return err
}

// UpdateRole 允许只传递需要覆盖修改的键值对（部分更新）。未包含的字段保持旧值。
func (c *Client) UpdateRole(ctx context.Context, name string, fields map[string]any) error {
	_, err := c.bao.Logical().WriteWithContext(ctx, c.p("roles/"+name), fields)
	return err
}

func (c *Client) GetRole(ctx context.Context, name string) (*api.Role, error) {
	sec, err := c.bao.Logical().ReadWithContext(ctx, c.p("roles/"+name))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("role %q not found", name)
	}
	res := &api.Role{}
	if err := decodeData(sec.Data, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *Client) ListRoles(ctx context.Context) ([]string, error) {
	sec, err := c.bao.Logical().ListWithContext(ctx, c.p("roles"))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return []string{}, nil
	}
	keys, ok := sec.Data["keys"].([]any)
	if !ok {
		return []string{}, nil
	}
	var res []string
	for _, k := range keys {
		if s, ok := k.(string); ok {
			res = append(res, strings.TrimSuffix(s, "/"))
		}
	}
	return res, nil
}

func (c *Client) DeleteRole(ctx context.Context, name string) error {
	_, err := c.bao.Logical().DeleteWithContext(ctx, c.p("roles/"+name))
	return err
}

// ---- Certs & Issue ----

func (c *Client) IssueCert(ctx context.Context, role string, opts api.IssueOptions) (*api.IssueResponse, error) {
	data := map[string]any{
		"common_name": opts.CommonName,
		"sync":        opts.Sync,
	}
	if len(opts.AltNames) > 0 {
		data["alt_names"] = opts.AltNames
		data["alternative_names"] = opts.AltNames
	}
	if opts.SkipPropagationCheck != nil {
		data["skip_propagation_check"] = *opts.SkipPropagationCheck
	}
	if opts.PropagationWait != nil {
		data["propagation_wait"] = *opts.PropagationWait
	}
	if len(opts.Resolvers) > 0 {
		data["resolvers"] = opts.Resolvers
	}

	sec, err := c.bao.Logical().WriteWithContext(ctx, c.p("certs/"+role), data)
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("empty response from issue cert")
	}

	res := &api.IssueResponse{}
	if err := decodeData(sec.Data, res); err != nil {
		return nil, err
	}
	return res, nil
}

// ListCerts 列出指定 role 或全部 (role 为空) 的已签发/缓存证书。
func (c *Client) ListCerts(ctx context.Context, role string) ([]api.CertSummary, error) {
	p := c.p("certs")
	if role != "" {
		p = c.p("certs/" + role + "/list")
	}

	sec, err := c.bao.Logical().ListWithContext(ctx, p)
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return []api.CertSummary{}, nil
	}

	rawCerts, ok := sec.Data["certificates"].([]any)
	if !ok {
		return []api.CertSummary{}, nil
	}

	var results []api.CertSummary
	for _, item := range rawCerts {
		if m, ok := item.(map[string]any); ok {
			var summary api.CertSummary
			if err := decodeData(m, &summary); err == nil {
				results = append(results, summary)
			}
		}
	}
	return results, nil
}

// GetCert 获取指定 role 下特定 CN 的证书详情。
func (c *Client) GetCert(ctx context.Context, role, cn string) (*api.CertDetail, error) {
	sec, err := c.bao.Logical().ReadWithContext(ctx, c.p("certs/"+role+"/"+cn))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("certificate %s/%s not found", role, cn)
	}

	res := &api.CertDetail{}
	if err := decodeData(sec.Data, res); err != nil {
		return nil, err
	}
	return res, nil
}

// RevokeCert 撤销并删除指定证书（向 CA 发送 Revoke 并清理缓存）。
func (c *Client) RevokeCert(ctx context.Context, role, cn string) error {
	_, err := c.bao.Logical().DeleteWithContext(ctx, c.p("certs/"+role+"/"+cn))
	return err
}

// RenewCert 主动触发已有证书的重新签发。
func (c *Client) RenewCert(ctx context.Context, role, cn string, sync bool) (*api.IssueResponse, error) {
	data := map[string]any{
		"sync": sync,
	}
	sec, err := c.bao.Logical().WriteWithContext(ctx, c.p("certs/"+role+"/"+cn+"/renew"), data)
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("empty response from renew cert")
	}

	res := &api.IssueResponse{}
	if err := decodeData(sec.Data, res); err != nil {
		return nil, err
	}
	return res, nil
}

// ---- Jobs ----

func (c *Client) GetJob(ctx context.Context, jobID string) (*api.JobDetail, error) {
	sec, err := c.bao.Logical().ReadWithContext(ctx, c.p("jobs/"+jobID))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("job %q not found", jobID)
	}

	res := &api.JobDetail{}
	if err := decodeData(sec.Data, res); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *Client) ListJobs(ctx context.Context) ([]string, error) {
	sec, err := c.bao.Logical().ListWithContext(ctx, c.p("jobs"))
	if err != nil {
		return nil, err
	}
	if sec == nil || sec.Data == nil {
		return []string{}, nil
	}
	keys, ok := sec.Data["keys"].([]any)
	if !ok {
		return []string{}, nil
	}
	var res []string
	for _, k := range keys {
		if s, ok := k.(string); ok {
			res = append(res, strings.TrimSuffix(s, "/"))
		}
	}
	return res, nil
}

func (c *Client) DeleteJob(ctx context.Context, jobID string) error {
	_, err := c.bao.Logical().DeleteWithContext(ctx, c.p("jobs/"+jobID))
	return err
}

// PruneJobs 批量清理终态 (completed / failed) 的 Job。
func (c *Client) PruneJobs(ctx context.Context, opts api.PruneJobOptions) ([]api.PrunedJobSummary, error) {
	jobIDs, err := c.ListJobs(ctx)
	if err != nil {
		return nil, fmt.Errorf("列出 Job 失败: %w", err)
	}

	now := time.Now()
	var pruned []api.PrunedJobSummary

	for _, id := range jobIDs {
		job, err := c.GetJob(ctx, id)
		if err != nil {
			// 可能刚被清理或不存在，跳过
			continue
		}

		// 只能清理终态 Job
		if job.Status != api.JobCompleted && job.Status != api.JobFailed {
			continue
		}

		// 仅清理失败任务
		if opts.FailedOnly && job.Status != api.JobFailed {
			continue
		}

		// 时间阈值过滤
		if opts.OlderThan > 0 {
			ts := job.UpdatedAt
			if ts == "" {
				ts = job.CreatedAt
			}
			t, parseErr := time.Parse(time.RFC3339, ts)
			if parseErr == nil && now.Sub(t) < opts.OlderThan {
				// 未达到超时期限，跳过
				continue
			}
		}

		// 执行删除
		if err := c.DeleteJob(ctx, id); err != nil {
			return pruned, fmt.Errorf("删除 job %s 失败: %w", id, err)
		}

		pruned = append(pruned, api.PrunedJobSummary{
			ID:        id,
			Role:      job.Role,
			Status:    job.Status,
			CN:        job.CommonName,
			UpdatedAt: job.UpdatedAt,
			Error:     job.Error,
		})
	}

	return pruned, nil
}

// PollJobUntilDone 轮询等待 Job 到达 completed 或 failed 状态。
func (c *Client) PollJobUntilDone(ctx context.Context, jobID string, pollInterval time.Duration, progressFn func(job *api.JobDetail)) (*api.JobDetail, error) {
	if pollInterval <= 0 {
		pollInterval = 1 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			detail, err := c.GetJob(ctx, jobID)
			if err != nil {
				return nil, err
			}
			if progressFn != nil {
				progressFn(detail)
			}
			switch detail.Status {
			case api.JobCompleted:
				return detail, nil
			case api.JobFailed:
				return detail, fmt.Errorf("job failed: %s", detail.Error)
			}
		}
	}
}

// FormatJSON 便捷方法格式化输出
func FormatJSON(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
