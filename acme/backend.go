package acme

import (
	"context"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Version 由 Makefile ldflags 注入；发布时为 v 前缀 SemVer，Factory 将其设为
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
	return b, nil
}

// backend 持有框架后端与签发链路依赖。
type backend struct {
	*framework.Backend
	credLoader CredentialLoader // 凭据实时读取器（KV）
	kvWriter   KVOutputWriter   // 证书 KV 输出
	issueGroup singleflight.Group
	cacheMu    sync.RWMutex
}

// —— 临时桩：Task 10 移入正式文件并实现 ——
type KVOutputWriter interface {
	Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error
}

type apiKVWriter struct{}

func (a *apiKVWriter) Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error {
	return nil
}
