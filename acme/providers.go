package acme

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/alidns"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/providers/dns/exec"
	"github.com/go-acme/lego/v5/providers/dns/tencentcloud"
)

// providerOpts 是 dns-providers 条目上的通用调参。
type providerOpts struct {
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

// providerBuilder 用凭据键值构造 lego provider。
type providerBuilder func(ctx context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error)

// registry 是 DNS provider 白名单；扩展新 provider 在此加一行。
var registry = map[string]providerBuilder{
	"cloudflare":   buildCloudflare,
	"alidns":       buildAliDNS,
	"tencentcloud": buildTencentCloud,
	"exec":         buildExec,
}

// envNames 是各 provider 认识的全部键名（凭据映射 keys 的合法左值）。
var envNames = map[string][]string{
	"cloudflare":   {"CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY", "CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_ZONE_API_TOKEN"},
	"alidns":       {"ALICLOUD_ACCESS_KEY", "ALICLOUD_RAM_ROLE", "ALICLOUD_REGION_ID", "ALICLOUD_SECRET_KEY", "ALICLOUD_SECURITY_TOKEN"},
	"tencentcloud": {"TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_REGION", "TENCENTCLOUD_SESSION_TOKEN"},
	"exec":         {"EXEC_PATH", "EXEC_MODE", "EXEC_PROPAGATION_TIMEOUT", "EXEC_POLLING_INTERVAL"},
}

// newProvider 按类型查注册表并构造 provider。
func newProvider(ctx context.Context, typeName string, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	build, ok := registry[typeName]
	if !ok {
		names := make([]string, 0, len(registry))
		for n := range registry {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("未知 dns provider 类型 %q（可用：%s）", typeName, strings.Join(names, ", "))
	}
	return build(ctx, opts, env)
}

func applyTimeouts(opts providerOpts, propagation, polling *time.Duration) {
	if opts.PropagationTimeout > 0 {
		*propagation = opts.PropagationTimeout
	}
	if opts.PollingInterval > 0 {
		*polling = opts.PollingInterval
	}
}

func buildCloudflare(_ context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	cfg, err := cloudflareConfig(env)
	if err != nil {
		return nil, err
	}
	applyTimeouts(opts, &cfg.PropagationTimeout, &cfg.PollingInterval)
	return cloudflare.NewDNSProviderConfig(cfg)
}

// cloudflareConfig 导出供测试断言。
func cloudflareConfig(env map[string]string) (*cloudflare.Config, error) {
	cfg := cloudflare.NewDefaultConfig()
	if v, ok := env["CLOUDFLARE_EMAIL"]; ok {
		cfg.AuthEmail = v
	}
	if v, ok := env["CLOUDFLARE_API_KEY"]; ok {
		cfg.AuthKey = v
	}
	if v, ok := env["CLOUDFLARE_DNS_API_TOKEN"]; ok {
		cfg.AuthToken = v
	}
	if v, ok := env["CLOUDFLARE_ZONE_API_TOKEN"]; ok {
		cfg.ZoneToken = v
	}
	if cfg.AuthToken == "" && (cfg.AuthKey == "" || cfg.AuthEmail == "") {
		return nil, fmt.Errorf("cloudflare: 需要 CLOUDFLARE_DNS_API_TOKEN 或 CLOUDFLARE_EMAIL+CLOUDFLARE_API_KEY（可用键：%s）",
			strings.Join(envNames["cloudflare"], ", "))
	}
	return cfg, nil
}

func buildAliDNS(_ context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	cfg, err := alidnsConfig(env)
	if err != nil {
		return nil, err
	}
	applyTimeouts(opts, &cfg.PropagationTimeout, &cfg.PollingInterval)
	return alidns.NewDNSProviderConfig(cfg)
}

func alidnsConfig(env map[string]string) (*alidns.Config, error) {
	cfg := alidns.NewDefaultConfig()
	if v, ok := env["ALICLOUD_ACCESS_KEY"]; ok {
		cfg.APIKey = v
	}
	if v, ok := env["ALICLOUD_RAM_ROLE"]; ok {
		cfg.RAMRole = v
	}
	if v, ok := env["ALICLOUD_SECRET_KEY"]; ok {
		cfg.SecretKey = v
	}
	if v, ok := env["ALICLOUD_SECURITY_TOKEN"]; ok {
		cfg.SecurityToken = v
	}
	if v, ok := env["ALICLOUD_REGION_ID"]; ok {
		cfg.RegionID = v
	}
	// RAMRole（ECS 实例 RAM 角色）是免 AK/SK 的独立认证路径，存在时豁免 APIKey+SecretKey 要求。
	if cfg.RAMRole == "" && (cfg.APIKey == "" || cfg.SecretKey == "") {
		return nil, fmt.Errorf("alidns: 需要 ALICLOUD_ACCESS_KEY+ALICLOUD_SECRET_KEY（可用键：%s）",
			strings.Join(envNames["alidns"], ", "))
	}
	return cfg, nil
}

func buildTencentCloud(_ context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	cfg, err := tencentcloudConfig(env)
	if err != nil {
		return nil, err
	}
	applyTimeouts(opts, &cfg.PropagationTimeout, &cfg.PollingInterval)
	return tencentcloud.NewDNSProviderConfig(cfg)
}

func tencentcloudConfig(env map[string]string) (*tencentcloud.Config, error) {
	cfg := tencentcloud.NewDefaultConfig()
	if v, ok := env["TENCENTCLOUD_SECRET_ID"]; ok {
		cfg.SecretID = v
	}
	if v, ok := env["TENCENTCLOUD_SECRET_KEY"]; ok {
		cfg.SecretKey = v
	}
	if v, ok := env["TENCENTCLOUD_REGION"]; ok {
		cfg.Region = v
	}
	if v, ok := env["TENCENTCLOUD_SESSION_TOKEN"]; ok {
		cfg.SessionToken = v
	}
	if cfg.SecretID == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("tencentcloud: 需要 TENCENTCLOUD_SECRET_ID+TENCENTCLOUD_SECRET_KEY（可用键：%s）",
			strings.Join(envNames["tencentcloud"], ", "))
	}
	return cfg, nil
}

// buildExec 构造 exec provider：外部程序负责真实 DNS 写/清（任意 DNS 商兜底、
// 私有 DNS、测试环境）。凭据键经 resolveKeys 以 env map 传入，作为子进程
// 环境的一部分（短暂私有，插件进程自身 env 不注入凭据）。EXEC_MODE 透传给
// lego（"RAW" 时子进程按 argv 收到 domain/token/keyAuth 原文）。
func buildExec(_ context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	cfg := exec.NewDefaultConfig()
	path, ok := env["EXEC_PATH"]
	if !ok || path == "" {
		return nil, fmt.Errorf("exec: 需要 EXEC_PATH（可用键：%s）", strings.Join(envNames["exec"], ", "))
	}
	cfg.Program = path
	if mode, ok := env["EXEC_MODE"]; ok {
		cfg.Mode = mode
	}
	if opts.PropagationTimeout > 0 {
		cfg.PropagationTimeout = opts.PropagationTimeout
	}
	if opts.PollingInterval > 0 {
		cfg.PollingInterval = opts.PollingInterval
	}
	return exec.NewDNSProviderConfig(cfg)
}
