package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type pebbleEnv struct {
	DirURL   string
	ChallSrv string
}

// startPebble 启动 pebble + challtestsrv 子进程并等待 /dir 就绪；
// 二进制缺失时 Skip。测试对 pebble 自签证书的信任由 InsecureTLS 提供。
func startPebble(t *testing.T) *pebbleEnv {
	t.Helper()
	pebbleBin, err := exec.LookPath("pebble")
	if err != nil {
		t.Skip("pebble 不在 PATH（安装：go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest）")
	}
	challBin, err := exec.LookPath("pebble-challtestsrv")
	if err != nil {
		t.Skip("pebble-challtestsrv 不在 PATH（安装：go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest）")
	}

	dir := t.TempDir()
	certPEM, keyPEM, err := selfSignedCertPEM()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600))

	cfg, err := json.Marshal(map[string]any{"pebble": map[string]any{
		"listenAddress": "127.0.0.1:14000",
		"certificate":   filepath.Join(dir, "cert.pem"),
		"privateKey":    filepath.Join(dir, "key.pem"),
		"httpPort":      8055,
		"tlsPort":       5001,
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pebble-config.json"), cfg, 0o600))

	env := &pebbleEnv{DirURL: "https://127.0.0.1:14000/dir", ChallSrv: "http://127.0.0.1:8055"}
	pebble := exec.Command(pebbleBin, "-config", filepath.Join(dir, "pebble-config.json"),
		"-dnsserver", "127.0.0.1:8053")
	pebble.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1")
	pebble.Stdout, pebble.Stderr = os.Stdout, os.Stderr
	// challtestsrv 的 -http01/-tlsalpn01/-dnsserver 均为完整 bind 地址；
	// 禁用 DoH、management 移至 8056，避免多实例/多端口语义冲突。
	challsrv := exec.Command(challBin, "-http01", ":8055", "-tlsalpn01", ":5001",
		"-dnsserver", ":8053", "-doh", "", "-management", ":8056",
		"-defaultIPv4", "127.0.0.1")
	challsrv.Stdout, challsrv.Stderr = os.Stdout, os.Stderr
	require.NoError(t, pebble.Start())
	require.NoError(t, challsrv.Start())
	t.Cleanup(func() {
		_ = pebble.Process.Kill()
		_, _ = pebble.Process.Wait()
		_ = challsrv.Process.Kill()
		_, _ = challsrv.Process.Wait()
	})

	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(env.DirURL)
		if err == nil {
			_ = resp.Body.Close()
			return env
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("pebble 未在 15s 内就绪")
	return nil
}

// selfSignedCertPEM 生成 pebble 用的自签证书。
func selfSignedCertPEM() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pebble"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
