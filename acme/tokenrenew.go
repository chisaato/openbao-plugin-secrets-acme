package acme

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
)

// tokenAuthClient 抽象 token 检查与 renew-self 调用；测试注入 fake（仿 CredentialLoader 模式）。
type tokenAuthClient interface {
	lookupSelf(ctx context.Context) (*api.Secret, error)
	renewSelf(ctx context.Context) (ttl time.Duration, err error)
}

// apiTokenAuthClient 以插件进程 env（BAO_ADDR/BAO_TOKEN 或 VAULT_*）身份调用
// /v1/auth/token/lookup-self 与 /v1/auth/token/renew-self。
// increment 传 0：periodic token 由服务端重置为 period，传非零 increment 反而引入
// max_ttl 语义干扰。renew-self 只延长过期时间、不改变 token 字符串（服务端持久化 entry），
// 因此 env 里的值终身有效。
type apiTokenAuthClient struct{}

func (a *apiTokenAuthClient) lookupSelf(ctx context.Context) (*api.Secret, error) {
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, fmt.Errorf("create openbao client: %w", err)
	}
	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("lookup-self: %w", err)
	}
	return secret, nil
}

func (a *apiTokenAuthClient) renewSelf(ctx context.Context) (time.Duration, error) {
	client, err := api.NewClient(nil)
	if err != nil {
		return 0, fmt.Errorf("create openbao client: %w", err)
	}
	secret, err := client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return 0, fmt.Errorf("renew-self: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return 0, fmt.Errorf("renew-self: 响应缺少 auth 块")
	}
	// TTL 取 auth.lease_duration（秒）。
	return time.Duration(secret.Auth.LeaseDuration) * time.Second, nil
}

// tokenRenewer 周期性续期插件服务身份 token：启动即试一次（自愈长停机期间
// 过期的场景），成功后按 TTL/2 调度下次（下限 intervalFloor）；失败按指数
// 退避重试。任何续期失败都不会导致进程退出——续期是尽力而为的自愈机制。
type tokenRenewer struct {
	client tokenAuthClient
	logger hclog.Logger
	// 成功后下次续期间隔下限（生产 1min）：防止异常短的 TTL 打爆服务端。
	intervalFloor time.Duration
	// 失败退避初值/上限（生产 5min/30min）：指数退避避免对不可用服务端重试风暴。
	backoffInit time.Duration
	backoffMax  time.Duration
}

// newTokenRenewer 生产默认参数构造；测试可直接覆写间隔字段注入短值。
func newTokenRenewer(client tokenAuthClient, logger hclog.Logger) *tokenRenewer {
	return &tokenRenewer{
		client:        client,
		logger:        logger,
		intervalFloor: time.Minute,
		backoffInit:   5 * time.Minute,
		backoffMax:    30 * time.Minute,
	}
}

// isNonRenewableError 判定 renew-self 返回的错误是否表明 token 不可续期。
// 常见情况包括 HTTP 400 下的 "invalid lease ID"、"token is not renewable"、"lease not found" 等。
func isNonRenewableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "invalid lease id") ||
		strings.Contains(msg, "not renewable") ||
		strings.Contains(msg, "lease not found")
}

// checkTokenRenewable 检查 token 是否支持续期。
// 返回 renewable (bool), reason (string), error。
// 如果 lookup 遇到权限问题或网络错误，返回 err 让调用方降级尝试 renew-self。
func checkTokenRenewable(secret *api.Secret) (bool, string) {
	if secret == nil {
		return true, ""
	}

	// 1. policies 是否包含 root
	policies, err := secret.TokenPolicies()
	if err == nil {
		for _, p := range policies {
			if p == "root" {
				return false, "token 拥有 root policy"
			}
		}
	}

	// 2. TokenIsRenewable()
	renewable, err := secret.TokenIsRenewable()
	if err == nil && !renewable {
		return false, "token 标记为不可续期 (renewable=false)"
	}

	// 3. TokenTTL()
	ttl, err := secret.TokenTTL()
	if err == nil && ttl == 0 {
		return false, "token TTL 为 0"
	}

	return true, ""
}

// run 续期主循环：ctx 取消即退出。
func (r *tokenRenewer) run(ctx context.Context) {
	// 启动续期循环前，先尝试 lookup-self 进行 token 性质预检
	if secret, err := r.client.lookupSelf(ctx); err == nil && secret != nil {
		if renewable, reason := checkTokenRenewable(secret); !renewable {
			r.logger.Info("服务身份 token 不可续期（如 root token 或静态 token），跳过自动续期循环", "reason", reason)
			return
		}
	} else if err != nil && ctx.Err() != nil {
		return
	}

	backoff := r.backoffInit
	for {
		ttl, err := r.client.renewSelf(ctx)
		if ctx.Err() != nil {
			// ctx 已取消：续期请求的结果无关紧要，直接退出。
			return
		}
		if err != nil {
			if isNonRenewableError(err) {
				r.logger.Info("服务身份 token 不可续期（如 root token 或静态 token），跳过自动续期循环", "error", err)
				return
			}
			// 只 warn 不退出：服务端短暂不可用（重启/封印）是常态，退避自愈。
			r.logger.Warn("服务身份 token 续期失败，稍后重试", "error", err, "retry_in", backoff.String())
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, r.backoffMax)
			continue
		}
		if ttl <= 0 {
			// TTL==0：root 等无 TTL/不可续期 token，无需也不应续期，停止循环。
			r.logger.Info("服务身份 token 不可续期（如 root token 或静态 token），跳过自动续期循环", "ttl", ttl.String())
			return
		}
		next := ttl / 2
		if next < r.intervalFloor {
			next = r.intervalFloor
		}
		r.logger.Info("服务身份 token 续期成功", "ttl", ttl.String(), "next_renew_in", next.String())
		if !sleepCtx(ctx, next) {
			return
		}
		// 成功过一次后重置退避：下次失败从初值重新爬升。
		backoff = r.backoffInit
	}
}

// sleepCtx 可中断休眠；返回 false 表示 ctx 已取消。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// tokenRenewDisabled 读 BAO_TOKEN_RENEW_DISABLE 逃生口：非空且非 "0"/"false"
// （大小写不敏感）时禁用内置续期循环——外部续期（如 cron）或本地 root token
// 测试不想看到不可续期警告时使用。
func tokenRenewDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BAO_TOKEN_RENEW_DISABLE")))
	return v != "" && v != "0" && v != "false"
}

// startTokenRenewer 由 Factory（生产入口）在 Setup 成功后调用；直接调用
// Backend() 的单测路径不经过此函数，保持现有测试零影响。
// 循环 ctx 不派生自 Factory ctx——那是挂载操作上下文，生命周期不可控；
// 以 Clean 回调为唯一停止信号（sdk Cleanup(ctx) 卸载时调用）。
func (b *backend) startTokenRenewer() {
	logger := b.Logger()
	if tokenRenewDisabled() {
		logger.Info("BAO_TOKEN_RENEW_DISABLE 已设置，跳过服务身份 token 自动续期")
		return
	}
	client := b.renewClient
	if client == nil {
		client = &apiTokenAuthClient{}
	}
	// cancel 被下面的 Clean 闭包捕获，无需额外字段/锁：Factory 同步创建两者，
	// Clean 由 core 在卸载时调用（Factory 返回之后）。
	ctx, cancel := context.WithCancel(context.Background())
	b.Clean = func(_ context.Context) {
		cancel()
	}
	go newTokenRenewer(client, logger).run(ctx)
}
