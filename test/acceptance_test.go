// Package test 是验收测试（独立 go module，避免把测试依赖混入插件构建）。
//
// 全链路离线 e2e：真实 bao server -dev + 插件注册（sha256）+ pebble/challtestsrv，
// 覆盖 exec provider 真实签发（TXT 落地 challtestsrv）、KV 输出读回、缓存命中、
// 双 lease 撤销 → pebble cert-status-by-serial 真实证书状态。
//
// 离线保证：account server_url 指向本地 pebble（insecure_tls）；DNS-01 走 exec
// provider 本地脚本调 challtestsrv 管理 API；凭据全为本地假值；插件进程注入
// LEGO_DISABLE_CNAME_SUPPORT 跳过 CNAME 公网解析；dns-provider 开启
// skip_propagation_check 跳过 lego 主动传播预检（默认预检会轮询公网权威 NS）。
// 任何路径不访问 api.letsencrypt.org 或真实 DNS API。
package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	api "github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
)

const (
	rootToken    = "acme-acc-root"
	pluginName   = "openbao-plugin-secrets-acme"
	pluginVer    = "v0.1.0"
	pebbleDirURL = "https://127.0.0.1:14000/dir"
	challMgmtURL = "http://127.0.0.1:8056"
)

// ---- 子进程管理 ----

func startProc(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	require.NoError(t, cmd.Start(), "启动 %s 失败", name)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

// startPebble 拉起 pebble + challtestsrv（端口约定与 acme/pebble_test.go 一致：
// dir 14000 / mgmt 8056 / dns 8053 / http01 8055 / tlsalpn 5001；pebble 管理
// API 默认 15000 用于 cert-status-by-serial）。
func startPebble(t *testing.T) {
	t.Helper()
	pebbleBin, err := exec.LookPath("pebble")
	if err != nil {
		t.Skip("pebble 不在 PATH")
	}
	challBin, err := exec.LookPath("pebble-challtestsrv")
	if err != nil {
		t.Skip("pebble-challtestsrv 不在 PATH")
	}

	dir := t.TempDir()
	certPEM, keyPEM := selfSignedCertPEM(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600))

	cfg, err := json.Marshal(map[string]any{"pebble": map[string]any{
		"listenAddress": "127.0.0.1:14000",
		"certificate":   filepath.Join(dir, "cert.pem"),
		"privateKey":    filepath.Join(dir, "key.pem"),
		"httpPort":      8055,
		"tlsPort":       5001,
		// 管理接口（cert-status-by-serial）需显式声明，缺省不启动。
		"managementListenAddress": "127.0.0.1:15000",
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pebble-config.json"), cfg, 0o600))

	startProc(t, pebbleBin, "-config", filepath.Join(dir, "pebble-config.json"),
		"-dnsserver", "127.0.0.1:8053")
	startProc(t, challBin, "-http01", ":8055", "-tlsalpn01", ":5001",
		"-dnsserver", ":8053", "-doh", "", "-management", ":8056",
		"-defaultIPv4", "127.0.0.1")

	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(pebbleDirURL)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("pebble 未在 15s 内就绪")
}

func selfSignedCertPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
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
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// startBaoDev 构建插件二进制并启动 bao server -dev（随机 API 端口 +
// -dev-plugin-dir），返回就绪的 api client 与插件目录。
func startBaoDev(t *testing.T) *api.Client {
	t.Helper()
	goBin, err := exec.LookPath("go")
	require.NoError(t, err, "go 不在 PATH")

	repoRoot, err := filepath.Abs("..")
	require.NoError(t, err)
	pluginDir := filepath.Join(t.TempDir(), "plugins")
	require.NoError(t, os.MkdirAll(pluginDir, 0o755))
	binPath := filepath.Join(pluginDir, pluginName)

	// 与 justfile build 相同的 ldflags：Version 必须是 v 前缀 SemVer。
	build := exec.Command(goBin, "build",
		"-ldflags", "-X github.com/chisaato/openbao-plugin-secrets-acme/acme.Version="+pluginVer,
		"-o", binPath, "./cmd/plugin")
	build.Dir = repoRoot
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	require.NoError(t, build.Run(), "插件构建失败")

	// sha256 注册（brief：bao plugin register -sha256=...）。
	sum, err := sha256File(binPath)
	require.NoError(t, err)

	// 随机 API 端口：先占 :0 拿端口再释放（微竞态可接受）。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	home := t.TempDir()
	env := append(os.Environ(),
		// 插件子进程经 server 继承：apiKVWriter/apiCredentialLoader 的
		// api.NewClient(nil) 依赖该地址与 token（ClientToken 传给插件前
		// 已被 core salted+hashed，不可用作身份）；CNAME 禁用避免公网解析。
		"BAO_ADDR=http://"+addr,
		"BAO_TOKEN="+rootToken,
		"LEGO_DISABLE_CNAME_SUPPORT=true",
		"HOME="+home)
	cmd := exec.Command("bao", "server", "-dev",
		"-dev-root-token-id="+rootToken,
		"-dev-listen-address="+addr,
		"-dev-plugin-dir="+pluginDir)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	require.NoError(t, cmd.Start(), "bao server 启动失败")
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	client, err := api.NewClient(&api.Config{Address: "http://" + addr})
	require.NoError(t, err)
	client.SetToken(rootToken)

	// 等待 dev server 就绪。
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Sys().Health(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := client.Sys().Health(); err != nil {
		t.Fatalf("bao server 未就绪: %v", err)
	}

	require.NoError(t, client.Sys().RegisterPlugin(&api.RegisterPluginInput{
		Type:    api.PluginTypeSecrets,
		Name:    pluginName,
		Command: pluginName,
		SHA256:  sum,
		Version: pluginVer,
	}), "插件注册失败")
	return client
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// respOK 断言 logical 写操作成功（openbao 写成功惯例返回 nil resp）。
func respOK(t *testing.T, resp *api.Secret, err error) {
	t.Helper()
	require.NoError(t, err)
	if resp == nil {
		return
	}
	if warn, ok := resp.Data["warnings"]; ok {
		t.Logf("warnings: %v", warn)
	}
}

// ---- challtestsrv 管理 API 助手 ----

func postMgmt(t *testing.T, endpoint string, body any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(challMgmtURL+endpoint, "application/json", strings.NewReader(string(raw)))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s 应成功", endpoint)
}

// dnsTXT 向 challtestsrv 的 DNS 端口（8053）直接查询 TXT，验证记录真实落地。
// 不用 net.Resolver：其对 challtestsrv 的权威应答会误判 "lame referral"。
func dnsTXT(t *testing.T, fqdn string) []string {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	c := new(dns.Client)
	c.Net = "udp"
	resp, _, err := c.Exchange(m, "127.0.0.1:8053")
	require.NoError(t, err, "DNS TXT 查询失败")
	out := make([]string, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(txt.Txt, ""))
		}
	}
	return out
}

// ---- pebble 证书状态（管理 API 15000） ----

// pebbleCertStatus 按 serial 多格式探测 pebble /cert-status-by-serial。
func pebbleCertStatus(t *testing.T, certPEM string) (string, error) {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "证书 PEM 解析失败")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// serial 文本形式存在前导零差异，多格式尝试。
	serials := []string{
		strings.ToLower(cert.SerialNumber.Text(16)),
		strings.ToUpper(cert.SerialNumber.Text(16)),
		hex.EncodeToString(cert.SerialNumber.Bytes()),
		strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes())),
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	for _, s := range serials {
		resp, err := client.Get("https://127.0.0.1:15000/cert-status-by-serial/" + s)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var out struct {
			Status string `json:"Status"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return "", err
		}
		return out.Status, nil
	}
	return "", fmt.Errorf("pebble 未找到 serial %s 的证书状态", cert.SerialNumber.Text(16))
}

func waitCertStatus(t *testing.T, certPEM, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		status, err := pebbleCertStatus(t, certPEM)
		if err == nil {
			last = status
			if strings.EqualFold(status, want) {
				return status
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("pebble 证书状态未变为 %q（当前 %q）", want, last)
	return ""
}

// ---- 验收主用例 ----

func TestAcceptanceFullPipeline(t *testing.T) {
	// 前置检查：依赖缺失时 skip（不污染 CI）。
	for _, bin := range []string{"bao", "curl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s 不在 PATH", bin)
		}
	}
	startPebble(t)
	client := startBaoDev(t)
	ctx := context.Background()

	// ---- mount + 插件版本（ldflags 注入链路验证）----
	require.NoError(t, client.Sys().Mount("acme", &api.MountInput{
		Type: pluginName,
		Config: api.MountConfigInput{
			PluginVersion: pluginVer,
		},
	}), "启用插件 mount 失败")
	mounts, err := client.Sys().ListMounts()
	require.NoError(t, err)
	mo, ok := mounts["acme/"]
	require.True(t, ok, "acme/ 未挂载")
	require.Equal(t, pluginName, mo.Type)
	// 版本断言（MountOutput 直接暴露 plugin_version/running_plugin_version）：
	// PluginVersion 是 mount 时声明的版本；RunningVersion 是插件进程自报的
	// 运行版本（Factory 将 ldflags 注入的 acme.Version 设为 RunningVersion）
	// ——两者都等于 v0.1.0 即验证了 just build 的 ldflags 注入链路。
	// 注意：不要读 Options["version"]——server mount 后把 version option
	// 提升为 plugin_version 并从 Options 移除（OpenBao 2.x 行为，实测确认）；
	// 也不要比对 test module 里的 acme.Version——独立编译无 ldflags，恒 "dev"。
	require.Equal(t, pluginVer, mo.PluginVersion, "mount 配置版本应与注册版本一致")
	require.Equal(t, pluginVer, mo.RunningVersion, "插件自报运行版本应为 ldflags 注入的 v0.1.0")

	// ---- 预置凭据 KV（全为本地假值；EXEC_MODE_TIMEOUT 照 brief 逐字保留，
	// exec builder 不识别该键，resolveKeys 白名单外自动忽略）----
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "acme-dns.sh")
	repoRoot, err := filepath.Abs("..")
	require.NoError(t, err)
	src, err := os.ReadFile(filepath.Join(repoRoot, "test", "acme-dns.sh"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(scriptPath, src, 0o755))
	_, err = client.KVv2("secret").Put(ctx, "dns/exec", map[string]any{
		"EXEC_PATH":         scriptPath,
		"EXEC_MODE_TIMEOUT": "20s",
	})
	require.NoError(t, err, "预置凭据 KV 失败")

	// ---- dns-provider（type=exec + 跳过传播预检）----
	dnsResp, err := client.Logical().Write("acme/dns-providers/exec", map[string]any{
		"type":                   "exec",
		"credentials_ref":        map[string]any{"mount": "secret", "path": "dns/exec"},
		"skip_propagation_check": true,
		"propagation_wait":       1,
	})
	respOK(t, dnsResp, err)
	read, err := client.Logical().Read("acme/dns-providers/exec")
	require.NoError(t, err)
	require.NotNil(t, read)
	require.Equal(t, "exec", read.Data["type"])
	require.Equal(t, true, read.Data["skip_propagation_check"])
	// 凭据引用不得回显。
	require.Empty(t, read.Data["credentials_ref"])

	// ---- account（指向本地 pebble）----
	accResp, err := client.Logical().Write("acme/accounts/le", map[string]any{
		"server_url":              pebbleDirURL,
		"contact":                 "admin@example.com",
		"terms_of_service_agreed": true,
		"insecure_tls":            true,
		"dns_providers":           []any{map[string]any{"name": "exec"}},
	})
	respOK(t, accResp, err)

	// ---- role ----
	roleResp, err := client.Logical().Write("acme/roles/web", map[string]any{
		"account":            "le",
		"allowed_domains":    "example.com",
		"allow_bare_domains": true,
		"output_kv_mount":    "secret",
	})
	respOK(t, roleResp, err)

	// ---- exec 脚本直测：TXT 真落地 challtestsrv（DNS 协议可查）----
	t.Run("ScriptWritesTXT", func(t *testing.T) {
		const fqdn = "_acme-challenge.example.com."
		// lego v5 exec 以 argv 调用：<script> present <fqdn> <value>。
		out, err := exec.Command(scriptPath, "present", fqdn, "dummy-key-auth").CombinedOutput()
		require.NoError(t, err, "脚本 present 失败: %s", out)
		require.Equal(t, []string{"dummy-key-auth"}, dnsTXT(t, fqdn))

		_, err = exec.Command(scriptPath, "cleanup", fqdn, "dummy-key-auth").CombinedOutput()
		require.NoError(t, err, "脚本 cleanup 失败")
		require.Empty(t, dnsTXT(t, fqdn))
	})

	// ---- 签发 + KV 输出 ----
	issue1, err := client.Logical().Write("acme/certs/web", map[string]any{"common_name": "example.com", "sync": true})
	require.NoError(t, err, "首次签发失败")
	require.NotNil(t, issue1)
	certPEM1, _ := issue1.Data["certificate"].(string)
	require.NotEmpty(t, certPEM1, "签发响应应含 certificate")
	require.NotEmpty(t, issue1.Data["private_key"], "签发响应应含 private_key")
	outputPath, _ := issue1.Data["output_path"].(string)
	require.Equal(t, "certs/web/example.com", outputPath)
	require.NotEmpty(t, issue1.Data["url"], "签发响应应含 cert url")

	kv, err := client.KVv2("secret").Get(ctx, "certs/web/example.com")
	require.NoError(t, err, "KV 输出读回失败")
	require.Equal(t, certPEM1, kv.Data["certificate"], "KV 输出 certificate 应与签发响应一致")
	require.Equal(t, issue1.Data["private_key"], kv.Data["private_key"])
	// JSON 反序列化后 domains 为 []interface{}。
	require.Equal(t, []any{"example.com"}, kv.Data["domains"])

	// ---- 二次签发：缓存命中（同 cert url）----
	issue2, err := client.Logical().Write("acme/certs/web", map[string]any{"common_name": "example.com", "sync": true})
	require.NoError(t, err, "二次签发失败")
	require.NotNil(t, issue2)
	require.Equal(t, issue1.Data["url"], issue2.Data["url"], "二次签发应命中缓存（同 cert url）")
	require.Equal(t, certPEM1, issue2.Data["certificate"])
	// 命中路径纯读不写 KV，但 output_path 仍指向签发时写入的既有数据。
	require.Equal(t, outputPath, issue2.Data["output_path"])
	// I-2：缓存命中不得产生 KV 新版本（签发时 version 1，命中后仍只有 1 版）。
	meta, err := client.KVv2("secret").GetMetadata(ctx, "certs/web/example.com")
	require.NoError(t, err, "读取 KV metadata 失败")
	require.Len(t, meta.Versions, 1, "缓存命中不得重写 KV（版本数应保持 1）")

	// ---- 双 lease 撤销：第一个撤销后 pebble 仍 valid（refcount=1），第二个后 revoked ----
	leases, err := client.Logical().List("sys/leases/lookup/acme/certs/web")
	require.NoError(t, err)
	require.NotNil(t, leases)
	keys, _ := leases.Data["keys"].([]any)
	require.Len(t, keys, 2, "两次签发应建立两个 lease")

	leaseID0 := "acme/certs/web/" + keys[0].(string)
	leaseID1 := "acme/certs/web/" + keys[1].(string)

	require.NoError(t, client.Sys().RevokePrefix(leaseID0), "第一次 lease 撤销失败")
	waitCertStatus(t, certPEM1, "valid") // 剩余 lease 持有引用，证书不得撤销

	require.NoError(t, client.Sys().RevokePrefix(leaseID1), "第二次 lease 撤销失败")
	waitCertStatus(t, certPEM1, "revoked") // 引用归零 → 向 pebble 真撤销
}
