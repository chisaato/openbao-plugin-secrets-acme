package acme

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathCache(b *backend) []*framework.Path {
	return []*framework.Path{{
		Pattern:         "cache/?$",
		HelpSynopsis:    "查看或清空共享证书缓存。",
		HelpDescription: "GET 返回当前缓存的共享证书条目数；DELETE 清空全部条目并返回清除数量。注意：清空缓存后，现存 lease 的 revoke 不再触发 ACME 服务端真撤销，只会优雅结束本地引用回收。",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Summary: "返回当前缓存的证书条目数。",
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					n, err := b.cacheCount(ctx, req.Storage)
					if err != nil {
						return nil, err
					}
					return &logical.Response{Data: map[string]interface{}{"cached_certs": n}}, nil
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Summary:     "清空全部缓存条目。",
				Description: "返回被清除的条目数量。注意：清空缓存后，现存 lease 的 revoke 因找不到缓存条目而不再触发 ACME 服务端真撤销（仅做本地回收）；被清空证书需等待其在服务端自然到期。",
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					n, err := b.cacheClear(ctx, req.Storage)
					if err != nil {
						return nil, err
					}
					return &logical.Response{Data: map[string]interface{}{"cleared": n}}, nil
				},
			},
		},
	}}
}
