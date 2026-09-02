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

// sanitizeCN 把 CN 变成 KV 路径安全的段：*. 前缀 → _wildcard.，/ → _。
func sanitizeCN(cn string) string {
	out := cn
	if strings.HasPrefix(out, "*.") {
		out = "_wildcard." + out[2:]
	}
	return strings.ReplaceAll(out, "/", "_")
}

// outputKVPath：certs/{role}/{sanitizeCN}。
func outputKVPath(roleName, cn string) string {
	return "certs/" + roleName + "/" + sanitizeCN(cn)
}

// writeCertOutput：未配置 OutputKVMount 时 no-op；否则以调用者 token 写证书
// 并返回写入的 KV path（由调用方拼装响应）。错误含 mount/path 定位信息。
func (b *backend) writeCertOutput(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, cn string, entry *cacheEntry) (string, error) {
	if role.OutputKVMount == "" {
		return "", nil
	}
	path := outputKVPath(roleName, cn)
	data := map[string]interface{}{
		"certificate": entry.CertificatePEM,
		"private_key": entry.PrivateKeyPEM,
		"issuer_cert": entry.IssuerCertificatePEM,
		"domains":     entry.Domains,
	}
	// 解析失败时省略 not_before/not_after 但不阻断证书输出：证书本体是
	// 主要交付物，fail-open 与 certNeedsRenewal 的保守策略语义对齐。
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
