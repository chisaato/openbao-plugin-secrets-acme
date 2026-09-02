package acme

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

// keyTypes 是用户可见 key_type 到 lego KeyType 的白名单（创建后不可改）。
var keyTypes = map[string]certcrypto.KeyType{
	"EC256":   certcrypto.EC256,
	"EC384":   certcrypto.EC384,
	"RSA2048": certcrypto.RSA2048,
	"RSA4096": certcrypto.RSA4096,
	"RSA8192": certcrypto.RSA8192,
}

// dnsProviderRef 引用一个 dns-providers/{name} 条目；Zones 为空表示兜底。
type dnsProviderRef struct {
	Name  string   `json:"name"`
	Zones []string `json:"zones,omitempty"`
}

// accountEntry 是 accounts/{name} 的持久化记录。
type accountEntry struct {
	Name             string           `json:"name"`
	ServerURL        string           `json:"server_url"`
	Contact          string           `json:"contact"`
	TOSAgreed        bool             `json:"terms_of_service_agreed"`
	KeyType          string           `json:"key_type"`
	PrivateKeyPEM    string           `json:"private_key_pem"`
	RegistrationJSON string           `json:"registration_json"`
	InsecureTLS      bool             `json:"insecure_tls"`
	DNSProviders     []dnsProviderRef `json:"dns_providers"`
}

// 编译期断言：legoUser 实现 lego 账户接口。
var _ registration.User = (*legoUser)(nil)

// legoUser 把账户适配为 lego registration.User（v5：*acme.ExtendedAccount）。
type legoUser struct {
	Email        string
	Registration *acme.ExtendedAccount
	key          crypto.Signer
}

func (u *legoUser) GetEmail() string                       { return u.Email }
func (u *legoUser) GetRegistration() *acme.ExtendedAccount { return u.Registration }
func (u *legoUser) GetPrivateKey() crypto.Signer           { return u.key }

// generatePrivateKeyPEM 生成新账户私钥并返回 PKCS#8 PEM。
func generatePrivateKeyPEM(kt certcrypto.KeyType) (crypto.Signer, string, error) {
	key, err := certcrypto.GeneratePrivateKey(kt)
	if err != nil {
		return nil, "", fmt.Errorf("generate account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("marshal PKCS8: %w", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return key, pemStr, nil
}

// parsePrivateKeyPEM 从 PKCS#8 PEM 恢复私钥。
func parsePrivateKeyPEM(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("account key: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("account key of type %T is not a signer", key)
	}
	return signer, nil
}

// newLegoClient 为用户与 CA 目录构造 lego 客户端。
func newLegoClient(user *legoUser, serverURL string, insecureTLS bool) (*lego.Client, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = serverURL
	if insecureTLS {
		// 仅供 pebble 等自签测试 CA 使用；生产置 insecure_tls=false。
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
		cfg.HTTPClient = &http.Client{Transport: transport, Timeout: 60 * time.Second}
	}
	return lego.NewClient(cfg)
}
