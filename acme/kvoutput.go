package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	pluginapi "github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// KVOutputWriter 把签发结果同步写入 KV engine。
type KVOutputWriter interface {
	Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error
	// Read 读取路径现存数据；路径不存在返回 (nil, nil)。
	Read(ctx context.Context, clientToken, mount, path string) (map[string]interface{}, error)
	Delete(ctx context.Context, clientToken, mount, path string) error
}

// kvConflictError：KV 目标路径被非本次证书的数据占用。
type kvConflictError struct{ Path, Detail string }

func (e *kvConflictError) Error() string {
	return fmt.Sprintf("KV 路径 %s 被占用: %s", e.Path, e.Detail)
}

// kvWritePolicy 控制 writeCertOutput 在目标路径被占用时的行为。
type kvWritePolicy int

const (
	kvPolicyEnforce    kvWritePolicy = iota // 冲突返回 *kvConflictError
	kvPolicyOverwrite                       // force：跳过检查直接写
	kvPolicyBestEffort                      // 冲突跳过写并记 warn 日志，返回 ("", nil)
)

// kvMetaOrDash：占用详情字段取字符串，缺失/空值显示 "-"。
func kvMetaOrDash(v interface{}) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return "-"
}

// apiKVWriter 用插件进程自身的 api client 写 KVv2。地址与 token 来自插件
// 进程 env（BAO_ADDR/BAO_TOKEN 或 VAULT_*）——ClientToken 经 core salted+hashed
// 后传给插件，不能用作身份；部署须给插件注入专用 token（见 README）。
type apiKVWriter struct{}

func (a *apiKVWriter) Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error {
	// clientToken 是哈希值，仅保留在接口签名中以兼容 Fake 实现。
	_ = clientToken
	client, err := api.NewClient(nil)
	if err != nil {
		return fmt.Errorf("create openbao client: %w", err)
	}
	_, err = client.KVv2(mount).Put(ctx, path, data)
	if err != nil {
		return fmt.Errorf("write kv2 %s/%s: %w", mount, path, err)
	}
	return nil
}

func (a *apiKVWriter) Delete(ctx context.Context, clientToken, mount, path string) error {
	_ = clientToken
	client, err := api.NewClient(nil)
	if err != nil {
		return fmt.Errorf("create openbao client: %w", err)
	}
	err = client.KVv2(mount).DeleteMetadata(ctx, path)
	if err != nil {
		return fmt.Errorf("delete kv2 metadata %s/%s: %w", mount, path, err)
	}
	return nil
}

func (a *apiKVWriter) Read(ctx context.Context, clientToken, mount, path string) (map[string]interface{}, error) {
	// clientToken 是哈希值，仅保留在接口签名中以兼容 Fake 实现。
	_ = clientToken
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, fmt.Errorf("create openbao client: %w", err)
	}
	secret, err := client.KVv2(mount).Get(ctx, path)
	if err != nil {
		// 路径不存在：KVv2.Get 包装 ErrSecretNotFound；据此视为空路径。
		if errors.Is(err, api.ErrSecretNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("read kv2 %s/%s: %w", mount, path, err)
	}
	if secret == nil {
		return nil, nil
	}
	return secret.Data, nil
}

// sanitizeCN 把 CN 变成 KV 路径安全的段：*. 前缀 → _wildcard.，/ → _。
func sanitizeCN(cn string) string {
	out := cn
	if strings.HasPrefix(out, "*.") {
		out = "_wildcard." + out[2:]
	}
	return strings.ReplaceAll(out, "/", "_")
}

// outputKVPath：certs/{certID}，以证书唯一 ID 作为路径，避免 CN 重名冲突。
func outputKVPath(certID string) string {
	return "certs/" + certID
}

// buildFullChain 组装包含叶子证书与签发者证书的完整链 PEM。
func buildFullChain(certPEM, issuerPEM string) string {
	certTrimmed := strings.TrimSpace(certPEM)
	issuerTrimmed := strings.TrimSpace(issuerPEM)
	if certTrimmed == "" {
		return issuerTrimmed
	}
	if issuerTrimmed == "" {
		return certTrimmed
	}
	if certTrimmed == issuerTrimmed {
		return certTrimmed
	}
	if strings.Contains(certTrimmed, "-----BEGIN CERTIFICATE-----") && strings.Contains(issuerTrimmed, "-----BEGIN CERTIFICATE-----") {
		if strings.Contains(certTrimmed, issuerTrimmed) {
			return certTrimmed
		}
	}
	return certTrimmed + "\n\n" + issuerTrimmed
}

// effectiveOutputKVMount：投影生效 mount。证书显式 link 且条目记录了 mount 时
// 以条目为准（续签/rename 沿用 link 绑定位置），否则跟随 role 配置。
func effectiveOutputKVMount(role *roleEntry, entry *cacheEntry) string {
	if entry != nil && entry.OutputKVLinked && entry.OutputKVMount != "" {
		return entry.OutputKVMount
	}
	if role != nil {
		return role.OutputKVMount
	}
	return ""
}

// writeCertOutput：role 未配置 OutputKVMount 且条目未 link 时 no-op；否则写证书
// 并返回写入的 KV 相对 path（mount 内路径段）。
//
// 投影/冲突语义：KV 是投影、ACME 是事实源。写入前按 policy 检查目标路径占用——
// 空路径、或现存数据 cert_id 与本次一致（自己的旧版本）允许写；被其他证书或
// 外来数据占用时按 policy 拒绝/跳过。
//
// link 语义：entry.OutputKVLinked 置位时以条目记录的 Mount/PathOverride 为准
// （link 建立的绑定位置），续签/rename 因此不会漂回 role 配置；未置位时维持
// 跟随 role.OutputKVMount 的历史行为。
//
// 本函数会就地更新 entry 的投影字段（OutputKVMount/OutputKVPath/OutputKVStatus），
// 调用方负责持久化（cacheUpdate）。BestEffort 跳过时 Mount/Path 保持上次成功值——
// 它们是"最后成功写入位置"，撤销清理语义依赖 Mount。
func (b *backend) writeCertOutput(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, certID string, entry *cacheEntry, policy kvWritePolicy) (string, error) {
	mount := effectiveOutputKVMount(role, entry)
	if mount == "" {
		return "", nil
	}
	path := outputKVPath(certID)
	if entry.OutputKVPathOverride != "" {
		path = entry.OutputKVPathOverride
	}
	if policy != kvPolicyOverwrite {
		existing, err := b.kvWriter.Read(ctx, req.ClientToken, mount, path)
		if err != nil {
			// 读取失败无法判定占用：Enforce 保守拒绝，BestEffort 跳过写继续。
			if policy == kvPolicyBestEffort {
				// 跳过不更新 Mount/Path：保持上次成功写入位置（撤销清理依赖）。
				entry.OutputKVStatus = pluginapi.KVStatusSkippedError
				b.Logger().Warn("KV 输出跳过：占用检查失败", "path", path, "error", err)
				return "", nil
			}
			return "", fmt.Errorf("KV 占用检查失败: %w", err)
		}
		if existing != nil {
			if otherID, _ := existing["cert_id"].(string); otherID != certID {
				detail := "路径存在非本引擎写入的数据"
				if otherID != "" {
					detail = fmt.Sprintf("已被证书 cert_id=%s (common_name=%s, role=%s, account=%s) 占用",
						otherID, kvMetaOrDash(existing["common_name"]), kvMetaOrDash(existing["role"]), kvMetaOrDash(existing["account"]))
				}
				conflict := &kvConflictError{Path: path, Detail: detail}
				if policy == kvPolicyBestEffort {
					// 跳过不更新 Mount/Path：保持上次成功写入位置。
					entry.OutputKVStatus = pluginapi.KVStatusSkippedConflict
					b.Logger().Warn("KV 输出跳过：目标路径被占用", "path", path, "detail", detail)
					return "", nil
				}
				return "", conflict
			}
		}
	}
	fullchain := buildFullChain(entry.CertificatePEM, entry.IssuerCertificatePEM)

	data := map[string]interface{}{
		// acme.sh 风格标准化资产字段
		"cert":      entry.CertificatePEM,
		"key":       entry.PrivateKeyPEM,
		"ca":        entry.IssuerCertificatePEM,
		"fullchain": fullchain,

		// 保持原有别名以向下兼容
		"certificate": entry.CertificatePEM,
		"private_key": entry.PrivateKeyPEM,
		"issuer_cert": entry.IssuerCertificatePEM,

		// 扁平化元数据
		"cert_id":     certID,
		"common_name": entry.CN,
		"domains":     entry.Domains,
		"role":        roleName,
		"account":     entry.Account,
	}
	if entry.Account == "" && role != nil {
		data["account"] = role.Account
	}

	// 解析证书有效期
	if block, _ := pem.Decode([]byte(entry.CertificatePEM)); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			data["not_before"] = cert.NotBefore.UTC().Format(time.RFC3339)
			data["not_after"] = cert.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	if err := b.kvWriter.Write(ctx, req.ClientToken, mount, path, data); err != nil {
		return "", err
	}
	entry.OutputKVStatus = pluginapi.KVStatusWritten
	entry.OutputKVMount = mount
	// 记录完整输出路径：mount + "/" + 生效路径。
	entry.OutputKVPath = mount + "/" + path
	return path, nil
}

// deleteCertOutput：从 KV 中删除证书条目（如撤销或引用归零时）。
// entry 非空且记录了 OutputKVPathOverride 时按 override 路径删除，否则派生
// certs/{certID}；rename 迁移等无 entry 场景传 nil 保持派生行为。
func (b *backend) deleteCertOutput(ctx context.Context, clientToken, mount, certID string, entry *cacheEntry) error {
	if mount == "" || certID == "" {
		return nil
	}
	path := outputKVPath(certID)
	if entry != nil && entry.OutputKVPathOverride != "" {
		path = entry.OutputKVPathOverride
	}
	return b.kvWriter.Delete(ctx, clientToken, mount, path)
}
