package acme

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// secretCertType 是 certs/{role} 响应携带的 lease secret 类型。
const secretCertType = "acme_cert"

// secretCertFor 构造绑定 backend 的证书 secret。framework.Secret 的
// Renew/Revoke 回调没有 *backend 接收者，故在 Backend() 内以方法值绑定的
// 闭包形态注入（Renew: b.certRenew, Revoke: b.certRevoke），避免全局单例。
func secretCertFor(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretCertType,
		Fields: map[string]*framework.FieldSchema{
			"common_name":     {Type: framework.TypeString},
			"domains":         {Type: framework.TypeCommaStringSlice},
			"certificate":     {Type: framework.TypeString},
			"private_key":     {Type: framework.TypeString},
			"issuer_cert":     {Type: framework.TypeString},
			"url":             {Type: framework.TypeString},
			"cert_stable_url": {Type: framework.TypeString},
			// Task 11 响应契约补充的交付字段。
			"output_path": {Type: framework.TypeString},
			"not_before":  {Type: framework.TypeString},
			"not_after":   {Type: framework.TypeString},
		},
		Renew:  b.certRenew,
		Revoke: b.certRevoke,
	}
}

// certRenew：lease 续期回调（framework 按 InternalData["secret_type"] 路由）。
//
// 语义：
//   - 缓存条目缺失（cache DELETE / 并发撤销归零 / 命中路径 KV 失败连带删除）
//     → 空响应优雅降级：不误报、不 panic，交由 core 自动续 lease 至自然到期。
//   - 证书新鲜（certNeedsRenewal=false）→ 空响应，framework 自动续期，证书
//     与引用计数均不动。
//   - 证书过期 → 以原 role/account/参数重签（复用 doIssue：Users=1 覆写条目
//     并刷新 KV 输出），返回新数据与新 Secret（framework 据此延长 lease、
//     MaxTTL 跟随新证书剩余寿命）。
//
// lease↔refcount 对账：重签经 singleflight 合并，doIssue 的初始 Users=1
// 归属领导者对应的 lease；等待者拿到共享响应后同样会各自建 lease，故等待者
// 在返回前必须经 cacheUpdate 自增引用，维持 Users == 持有该条目的 lease 数。
func (b *backend) certRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req == nil || req.Secret == nil {
		return nil, fmt.Errorf("续期请求缺少 Secret")
	}
	key, _ := req.Secret.InternalData["cache_key"].(string)
	roleName, _ := req.Secret.InternalData["role"].(string)
	if key == "" || roleName == "" {
		return nil, fmt.Errorf("lease 缺少 cache_key/role InternalData")
	}

	entry, err := b.cacheGet(ctx, req.Storage, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		// 条目已被清理：无法重签也不报错（core 视为续期成功）。
		return &logical.Response{}, nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q 已删除，无法续期", roleName)
	}
	if !certNeedsRenewal(entry.CertificatePEM, role.CacheForRatio) {
		return &logical.Response{}, nil
	}

	// 用条目记录的签发账户（而非 role 当前指向）重签，保证与缓存证书同源；
	// role 若被改指其他 account，新旧 lease 的撤销仍各自作用于原账户证书。
	account, err := b.getAccount(ctx, req.Storage, entry.Account)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, fmt.Errorf("account %q 不存在，无法重签", entry.Account)
	}

	// 与命中路径共用 singleflight：同 key 并发重签只发一次 ACME Obtain。
	// executed 标记本调用者是否为领导者（在闭包内设置，等待者经 WaitGroup
	// 的 happens-before 可见）；领导者的引用即 doIssue 写入的初始 Users=1。
	executed := false
	v, err, _ := b.issueGroup.Do(key, func() (interface{}, error) {
		executed = true
		return b.doIssue(ctx, req, roleName, role, account, entry.CN, entry.Domains, key)
	})
	if err != nil {
		return nil, fmt.Errorf("重签失败: %w", err)
	}
	resp, ok := v.(*logical.Response)
	if !ok || resp == nil {
		return nil, fmt.Errorf("重签内部错误：意外的 singleflight 结果 %T", v)
	}
	if !executed {
		// 等待者：共享领导者的响应并为自己的 lease 建立引用，但缓存计数只含
		// 领导者的 1，须在单临界区补自增，否则并发撤销会提前归零误删条目。
		// 若条目此刻消失（极端竞争）则保守报错，由 core 稍后重试续期。
		if uerr := b.cacheUpdate(ctx, req.Storage, key, func(e *cacheEntry) *cacheEntry {
			e.Users++
			return e
		}); uerr != nil {
			return nil, uerr
		}
	}
	return resp, nil
}

// certRevoke：lease 撤销回调。引用计数原子递减（cacheUpdate 单写临界区，
// 防并发撤销丢失更新）；减到 0 时尽力向 ACME 服务端真撤销（任何失败仅放弃，
// 不阻断本地回收）并删除缓存条目。
func (b *backend) certRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req == nil || req.Secret == nil {
		return nil, fmt.Errorf("撤销请求缺少 Secret")
	}
	key, _ := req.Secret.InternalData["cache_key"].(string)
	if key == "" {
		return nil, fmt.Errorf("lease 缺少 cache_key InternalData")
	}

	// 条目不存在（整缓存清空 / 命中路径 KV 失败连带删除 / 他人撤销归零）
	// → 优雅返回：本地已无引用可回收，不得 panic 或误报。
	entry, err := b.cacheGet(ctx, req.Storage, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	// 原子读改写递减；fn 返回 nil 使 cacheUpdate 在同一临界区内删除条目，
	// 并发撤销不会因读到旧值而漏减、永不归零。
	zeroed := false
	err = b.cacheUpdate(ctx, req.Storage, key, func(e *cacheEntry) *cacheEntry {
		e.Users--
		if e.Users <= 0 {
			zeroed = true
			return nil
		}
		return e
	})
	if err != nil {
		// cacheGet 已确认存在；此处报错只可能是并发删除或存储故障。保守
		// 上抛：core 重试撤销时会走上方 miss 分支优雅结束。
		return nil, err
	}

	if zeroed {
		// 引用归零：尽力而为真撤销。account 可能已删、网络可能失败——每一层
		// 错误都只放弃真撤销，绝不影响上面已完成的本地回收（证书在服务端
		// 到期后自然失效）。撤销输入为 PEM bundle（lego 内部 ParsePEMBundle）。
		if account, aerr := b.getAccount(ctx, req.Storage, entry.Account); aerr == nil && account != nil {
			if user, uerr := account.legoUser(); uerr == nil {
				if client, cerr := newLegoClient(user, account.ServerURL, account.InsecureTLS); cerr == nil {
					_ = client.Certificate.Revoke(ctx, []byte(entry.CertificatePEM))
				}
			}
		}
	}
	return nil, nil
}
