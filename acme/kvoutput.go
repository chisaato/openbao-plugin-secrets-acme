package acme

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// KVOutputWriter 把签发结果同步写入 KV engine。
type KVOutputWriter interface {
	Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error
}

// apiKVWriter 用调用者 token 写 KVv2。地址来自插件进程 env（BAO_ADDR/VAULT_ADDR）。
type apiKVWriter struct{}

func (a *apiKVWriter) Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error {
	client, err := api.NewClient(nil)
	if err != nil {
		return fmt.Errorf("create openbao client: %w", err)
	}
	client.SetToken(clientToken)
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
	if err := b.kvWriter.Write(ctx, req.ClientToken, role.OutputKVMount, path, data); err != nil {
		return "", err
	}
	return path, nil
}
