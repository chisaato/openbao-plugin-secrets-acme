package acme

import (
	"context"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/tokenrenew"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Version 由 justfile ldflags 注入；发布时为 v 前缀 SemVer，Factory 将其设为
// framework.Backend.RunningVersion 向 core 自报。
var Version = "dev"

// Factory 是 OpenBao 插件入口。
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	// 服务身份 token 自续期仅在 Factory（生产入口）启动；Backend() 单测路径
	// 不启动，保持现有测试零影响。
	b.startTokenRenewer()
	return b, nil
}

// Backend 构造 backend；测试可直接调用后覆写 credLoader/kvWriter。
func Backend(conf *logical.BackendConfig) (*backend, error) {
	b := &backend{
		Backend: &framework.Backend{
			BackendType: logical.TypeLogical,
			Paths:       []*framework.Path{},
			Secrets:     []*framework.Secret{},
		},
		credLoader: &apiCredentialLoader{},
		kvWriter:   &apiKVWriter{},
	}
	b.RunningVersion = Version
	b.runningJobs = make(map[string]struct{})
	// 重启恢复入口：Factory（生产）挂载后由 core 调用 Initialize；直接调用
	// Backend() 的单测路径无人调 Initialize，保持零影响（spec §8）。
	b.InitializeFunc = b.initializeBackend
	b.Paths = paths(b)
	// 证书 secret 的 Renew/Revoke 回调需要 *backend，故按实例绑定注册。
	b.Secrets = []*framework.Secret{secretCertFor(b)}
	return b, nil
}

// startTokenRenewer 由 Factory（生产入口）在 Setup 成功后调用；直接调用
// Backend() 的单测路径不经过此函数，保持现有测试零影响。
// 循环 ctx 不派生自 Factory ctx——那是挂载操作上下文，生命周期不可控；
// 以 Clean 回调为唯一停止信号（sdk Cleanup(ctx) 卸载时调用）。
func (b *backend) startTokenRenewer() {
	logger := b.Logger()
	if tokenrenew.TokenRenewDisabled() {
		logger.Info("BAO_TOKEN_RENEW_DISABLE 已设置，跳过服务身份 token 自动续期")
		return
	}
	client := b.renewClient
	if client == nil {
		client = &tokenrenew.APITokenAuthClient{}
	}
	// cancel 被下面的 Clean 闭包捕获，无需额外字段/锁：Factory 同步创建两者，
	// Clean 由 core 在卸载时调用（Factory 返回之后）。
	ctx, cancel := context.WithCancel(context.Background())
	b.Clean = func(_ context.Context) {
		cancel()
	}
	go tokenrenew.NewTokenRenewer(client, logger).Run(ctx)
}

// paths 聚合全部路径；后续任务向此追加。
// paths 聚合全部路径；后续任务向此追加。
func paths(b *backend) []*framework.Path {

	paths := append(pathDNSProviders(b), pathAccounts(b)...)
	paths = append(paths, pathRoles(b)...)
	paths = append(paths, pathCertsExtended(b)...)
	paths = append(paths, pathCerts(b)...)
	paths = append(paths, pathJobs(b)...)
	return append(paths, pathCache(b)...)
}

// backend 持有框架后端与签发链路依赖。
type backend struct {
	*framework.Backend
	credLoader CredentialLoader // 凭据实时读取器（KV）
	kvWriter   KVOutputWriter   // 证书 KV 输出
	// dns01Opts 透传给 SetDNS01Provider 的附加选项。生产恒为 nil（零行为
	// 差异）；测试注入以控制 DNS 传播预检（如 PropagationWait skipCheck），
	// 使单测可用 challtestsrv 走通真实 ACME Obtain。
	dns01Opts []dns01.ChallengeOption
	// renewClient 为服务身份 token 续期实现；nil 时 startTokenRenewer 回退
	// APITokenAuthClient，测试注入 fake 以拦截真实网络调用。
	renewClient tokenrenew.TokenAuthClient
	issueGroup  singleflight.Group
	cacheMu     sync.RWMutex
	// issueFn 非空时替代真实 ACME Obtain（仅测试注入，仿 credLoader 模式）。
	issueFn func(ctx context.Context, req *logical.Request, account *accountEntry, domains []string) (*certificate.Resource, error)
	// jobMu/runningJobs：本进程内 job 单驱动防护（spec §8）。
	jobMu       sync.Mutex
	runningJobs map[string]struct{}
	// jobCtx：后台 Worker 长生命周期上下文（startJobRunner 设置；nil 回退 Background）。
	jobCtx context.Context
}
