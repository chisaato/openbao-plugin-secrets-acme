package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// KVOutputWriter 把签发结果同步写入 KV engine。
type KVOutputWriter interface {
	Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error
	Delete(ctx context.Context, clientToken, mount, path string) error
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

// writeCertOutput：未配置 OutputKVMount 时 no-op；否则写证书并返回写入的 KV path。
func (b *backend) writeCertOutput(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, certID string, entry *cacheEntry) (string, error) {
	if role.OutputKVMount == "" {
		return "", nil
	}
	path := outputKVPath(certID)
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
	if entry.Account == "" {
		data["account"] = role.Account
	}

	// 解析证书有效期
	if block, _ := pem.Decode([]byte(entry.CertificatePEM)); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			data["not_before"] = cert.NotBefore.UTC().Format(time.RFC3339)
			data["not_after"] = cert.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	if err := b.kvWriter.Write(ctx, req.ClientToken, role.OutputKVMount, path, data); err != nil {
		return "", err
	}
	return path, nil
}

// deleteCertOutput：从 KV 中删除证书条目（如撤销或引用归零时）。
func (b *backend) deleteCertOutput(ctx context.Context, clientToken, mount, certID string) error {
	if mount == "" || certID == "" {
		return nil
	}
	path := outputKVPath(certID)
	return b.kvWriter.Delete(ctx, clientToken, mount, path)
}
