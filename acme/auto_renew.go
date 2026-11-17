package acme

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	pluginapi "github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/tokenrenew"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// autoRenewDisabled 读 BAO_ACME_AUTORENEW_DISABLE 逃生口，语义与
// tokenrenew.TokenRenewDisabled 一致：非空且非 "0"/"false"（大小写不敏感）
// 即禁用后台自动续签循环——外部 cron 驱动 `cert renew` 的部署使用。
func autoRenewDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BAO_ACME_AUTORENEW_DISABLE")))
	return v != "" && v != "0" && v != "false"
}

// autoRenewInterval 读 BAO_ACME_AUTORENEW_INTERVAL 扫描间隔（Go duration
// 格式）。未设置、解析失败或非正值时回退默认 1h。
func autoRenewInterval() time.Duration {
	if v := strings.TrimSpace(os.Getenv("BAO_ACME_AUTORENEW_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// startAutoRenewer 由 initializeBackend 在 startJobRunner 之后调用：共享
// jobCtx（Clean 卸载时统一取消），后台周期扫描缓存并对临期证书自动重签。
// 必须晚于 startJobRunner——依赖其设置的 jobCtx（nil 时 workerCtx 回退
// Background，卸载无法取消）。
func (b *backend) startAutoRenewer(st logical.Storage) {
	if autoRenewDisabled() {
		b.Logger().Info("BAO_ACME_AUTORENEW_DISABLE 已设置，跳过证书自动续签循环")
		return
	}
	ctx := b.workerCtx()
	interval := autoRenewInterval()
	go func() {
		// 启动即首轮扫描（自愈长停机期间积压的临期证书），随后按间隔循环。
		for {
			b.autoRenewScan(ctx, st)
			if !tokenrenew.SleepCtx(ctx, interval) {
				return
			}
		}
	}()
}

// autoRenewScan 单轮扫描：按每条条目签发 role 的 CacheForRatio 判定新鲜度，
// 临期条目交 autoRenewOne 重签。role/account 已删除的条目只 warn 跳过，绝不
// 清理——清理属撤销语义，此处不得误删 lease 可能仍引用的条目。
func (b *backend) autoRenewScan(ctx context.Context, st logical.Storage) {
	logger := b.Logger()
	keys, err := st.List(ctx, storageKeyCache)
	if err != nil {
		logger.Warn("自动续签扫描失败", "error", err)
		return
	}
	for _, k := range keys {
		if ctx.Err() != nil {
			return
		}
		entry, err := b.cacheGet(ctx, st, k)
		if err != nil {
			logger.Warn("自动续签读取缓存条目失败，跳过", "cert_id", k, "error", err)
			continue
		}
		// 旧条目（无 role 字段）无法按 role 读 ratio，保守跳过。
		if entry == nil || entry.Role == "" {
			continue
		}
		role, err := b.getRole(ctx, st, entry.Role)
		if err != nil || role == nil {
			logger.Warn("自动续签跳过：签发 role 不存在", "cert_id", k, "role", entry.Role)
			continue
		}
		account, err := b.getAccount(ctx, st, entry.Account)
		if err != nil || account == nil {
			logger.Warn("自动续签跳过：签发 account 不存在", "cert_id", k, "account", entry.Account)
			continue
		}
		if !certNeedsRenewal(entry.CertificatePEM, role.CacheForRatio) {
			continue
		}
		b.autoRenewOne(ctx, st, k, role, account, entry)
	}
}

// autoRenewOne 重签单个临期条目。经 issueGroup.Do 与 lease 续期/显式续签/
// 并发扫描合并：同 key 只发一次 ACME Obtain。后台自身丢弃响应仅记日志；
// 并发 sync 签发等待者共享同一响应（语义同缓存命中，无 reused 标记）。
func (b *backend) autoRenewOne(ctx context.Context, st logical.Storage, key string, role *roleEntry, account *accountEntry, cur *cacheEntry) {
	logger := b.Logger()
	v, err, shared := b.issueGroup.Do(key, func() (interface{}, error) {
		return b.renewEntry(ctx, st, key, cur.Role, role, account)
	})
	if err != nil {
		logger.Warn("证书自动续签失败", "cert_id", key, "cn", cur.CN, "error", err)
		return
	}
	resp, ok := v.(*logical.Response)
	if !ok || resp == nil {
		logger.Warn("证书自动续签内部错误：意外的 singleflight 结果", "cert_id", key, "type", fmt.Sprintf("%T", v))
		return
	}
	if shared {
		logger.Info("证书自动续签已由并发调用者完成，共享其结果", "cert_id", key, "cn", cur.CN)
		return
	}
	logger.Info("证书自动续签完成", "cert_id", key, "cn", cur.CN, "domains", strings.Join(cur.Domains, ","))
}

// renewEntry 执行单条目后台重签（issueGroup.Do 闭包内调用，同 key 串行）。
//
// 与 doIssue 的关键差异（后台无对应 lease，不套用 Users=1 契约）：
//   - 不重置 Users：cacheUpdate 单临界区内原位覆写证书字段，保留存储当前
//     计数（并发命中路径的 Users++ 不丢失），维持 Users==lease 数不变式；
//   - KV 输出失败绝不删除缓存条目（同步路径 KV 硬失败整条删除靠调用方重签
//     自愈——后台删除会连带丢掉 lease 仍引用的证书），仅置 skipped_error
//     待下轮重试；
//   - 条目在 Obtain 期间被并发撤销归零删除时，仿异步 Job 以 Users=0 落回
//     新证书供后续命中复用。
//
// 返回值满足所有 singleflight 调用点的 *logical.Response 非空契约。
func (b *backend) renewEntry(ctx context.Context, st logical.Storage, key, roleName string, role *roleEntry, account *accountEntry) (*logical.Response, error) {
	cur, err := b.cacheGet(ctx, st, key)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		// 条目已被并发撤销/清理：无续签对象。并发等待者拿到空响应后经
		// waiterRefAdd 失败报错自愈（重试走 miss 路径）。
		return &logical.Response{}, nil
	}
	if !certNeedsRenewal(cur.CertificatePEM, role.CacheForRatio) {
		// 他人刚完成重签（或调用方绕过了 scan 新鲜度闸门）：不再 Obtain。
		return b.renewalResponse(cur, key, roleName, role), nil
	}

	// runJob 同款合成请求：真实 credLoader/kvWriter 忽略 ClientToken，以
	// 插件服务身份执行（env BAO_ADDR/BAO_TOKEN）。
	workerReq := &logical.Request{Storage: st, ClientToken: "auto-renew-worker"}
	res, err := b.obtainCert(ctx, workerReq, account, cur.Domains, nil)
	if err != nil {
		return nil, fmt.Errorf("ACME 重签: %w", err)
	}

	// 单写临界区内原位覆写证书字段：Users 与投影/link 字段保留存储现值
	//（KV 位置以条目记录为准，不漂回 role 现值）。
	var swapped *cacheEntry
	if uerr := b.cacheUpdate(ctx, st, key, func(e *cacheEntry) *cacheEntry {
		e.CertURL = res.CertURL
		e.CertStableURL = res.CertStableURL
		e.PrivateKeyPEM = string(res.PrivateKey)
		e.CertificatePEM = string(res.Certificate)
		e.IssuerCertificatePEM = string(res.IssuerCertificate)
		swapped = e
		return e
	}); uerr != nil {
		// 条目已并发消失（引用归零/缓存清空）：无 lease 持有，仿 runJob 以
		// Users=0 落回新证书，供后续请求精确命中复用。
		entry := &cacheEntry{
			Users:                0,
			Account:              account.Name,
			Role:                 roleName,
			CN:                   cur.CN,
			Domains:              cur.Domains,
			CertURL:              res.CertURL,
			CertStableURL:        res.CertStableURL,
			PrivateKeyPEM:        string(res.PrivateKey),
			CertificatePEM:       string(res.Certificate),
			IssuerCertificatePEM: string(res.IssuerCertificate),
			// 删除前条目的最后成功写入位置仍有效，继承以保撤销清理语义。
			OutputKVMount:        cur.OutputKVMount,
			OutputKVPath:         cur.OutputKVPath,
			OutputKVStatus:       cur.OutputKVStatus,
			OutputKVLinked:       cur.OutputKVLinked,
			OutputKVPathOverride: cur.OutputKVPathOverride,
		}
		if perr := b.cachePut(ctx, st, key, entry); perr != nil {
			return nil, fmt.Errorf("写缓存: %w", perr)
		}
		swapped = entry
	}

	// KV 投影 BestEffort 刷新（网络 I/O 在 cacheMu 临界区外）：冲突/读取失败
	// 由 writeCertOutput 置 skipped_* 并保持"最后成功写入位置"；仅 Write 网络
	// 失败返回错误——降级 skipped_error，绝不删除缓存条目。
	if _, kvErr := b.writeCertOutput(ctx, workerReq, roleName, role, key, swapped, kvPolicyBestEffort); kvErr != nil {
		swapped.OutputKVStatus = pluginapi.KVStatusSkippedError
		b.Logger().Warn("证书自动续签 KV 输出失败（保留条目待下轮重试）", "cert_id", key, "error", kvErr)
	}
	// writeCertOutput 就地更新了投影字段，同步进存储条目（best-effort：条目
	// 此刻被并发删除时放弃持久化，不影响续签结果）。
	_ = b.cacheUpdate(ctx, st, key, func(e *cacheEntry) *cacheEntry {
		e.OutputKVMount = swapped.OutputKVMount
		e.OutputKVPath = swapped.OutputKVPath
		e.OutputKVStatus = swapped.OutputKVStatus
		return e
	})

	return b.renewalResponse(swapped, key, roleName, role), nil
}

// renewalResponse 组装后台续签/复查命中路径的响应（并发 sync 等待者可能直接
// 把它服务给客户端）。语义与缓存命中一致：附证书有效期与 MaxTTL=剩余寿命；
// output_path 仅在 role 配置了 KV 输出时给出（同命中路径，不覆盖 linked
// 但 role 无 mount 的展示差异）。
func (b *backend) renewalResponse(entry *cacheEntry, key, roleName string, role *roleEntry) *logical.Response {
	kvPath := ""
	if role.OutputKVMount != "" {
		kvPath = outputKVPath(key)
	}
	resp := b.issueResponse(entry, key, role.Account, roleName, kvPath)
	if nb, na := certValidity(entry.CertificatePEM); !na.IsZero() {
		resp.Data["not_before"] = nb.Format(time.RFC3339)
		resp.Data["not_after"] = na.Format(time.RFC3339)
		// 剩余寿命即最大租期：并发 sync 等待者据此建 lease（同 respondWithCert）。
		resp.Secret.LeaseOptions.MaxTTL = time.Until(na)
	}
	return resp
}
