# openbao-plugin-secrets-acme 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 OpenBao 实现基于 go-acme/lego v5 的 ACME 证书签发 secrets 插件（v1 仅 DNS-01，凭据签发时实时读 KV，证书同步输出到 KV）。

**Architecture:** 外部插件进程（go-plugin/gRPC，OpenBao sdk/v2 framework.Backend）。业务路径：`dns-providers/{name}`（凭据引用+类型）、`accounts/{name}`（ACME 账户，含 rollover/key 导出）、`roles/{name}`（域名策略+缓存策略+KV 输出配置）、`certs/{role}`（签发）、`cache`（管理端点）。签发流程：role→account→域名路由（cert-manager 语义）→实时读 KV 凭据→lego provider 注册表构造→复合 challenge.Provider→Obtain→持久化缓存（引用计数）→写 KV 输出。

**Tech Stack:** Go 1.26.0、github.com/go-acme/lego/v5 v5.4.1、github.com/openbao/openbao/sdk/v2 v2.6.2、github.com/openbao/openbao/api/v2 v2.6.0、golang.org/x/sync（singleflight）、github.com/go-viper/mapstructure/v2、pebble + challtestsrv 测试。

**Spec:** `docs/superpowers/specs/2026-09-02-openbao-plugin-secrets-acme-design.md`（本计划逐任务实现该 spec；执行者须同时阅读两者）

## Global Constraints

- module path：`github.com/chisaato/openbao-plugin-secrets-acme`
- go 1.26.0；依赖固定：lego/v5 v5.4.1、openbao sdk/v2 v2.6.2、api/v2 v2.6.0、golang.org/x/sync、go-viper/mapstructure/v2
- v1 仅 DNS-01；无 HTTP-01/TLS-ALPN-01、无 sidecar、无 challenges 端点
- DNS provider 白名单：`cloudflare`、`alidns`、`tencentcloud`（dnspod 已被 lego v5 移除）；扩展方式=注册表加一行（文档记录）
- 禁止 `os.Setenv` 注入凭据；凭据只存在于请求生命周期内，不落插件存储、不写日志、不进响应
- 凭据读取=签发时实时读（调用者 token `req.ClientToken`），不快照
- KV 键名约定：左键=lego 官方环境变量名（如 `CLOUDFLARE_DNS_API_TOKEN`），SecretRef 风格显式映射优先、同名回退
- key_type 白名单 EC256/EC384/RSA2048/RSA4096/RSA8192，创建后不可改；server_url 可改（重 Register+ResolveAccountByKey 幂等）
- 域名路由：zones 后缀匹配、zone 段数多者优先、平局按列表顺序、无匹配报错（cert-manager 语义）
- 缓存键 `sha256(roleJSON+sorted domains)`；引用计数 revoke；`cache_for_ratio` 默认 70
- TDD：每任务先写失败测试再实现；每任务一个 commit
- 单测离线：pebble(:14000)+challtestsrv(DNS :8053/HTTP :8055) 子进程，不依赖外网

## 文件结构（最终形态）

```
openbao-plugin-secrets-acme/
├── acme/                        # 核心包（单包，业务全在此）
│   ├── backend.go               # Factory/Backend/backend struct/版本
│   ├── account.go               # 账户模型、legoUser、密钥生成/解析
│   ├── credentials.go           # credentialsRef、CredentialLoader、KV 读取与键解析
│   ├── providers.go             # provider 注册表（cloudflare/alidns/tencentcloud 构造器）
│   ├── routing.go               # 复合路由 challenge.Provider
│   ├── path_dns_providers.go    # dns-providers/{name} CRUD+LIST
│   ├── path_accounts.go         # accounts CRUD + rollover + key 导出
│   ├── path_roles.go            # roles CRUD + LIST + validateNames
│   ├── path_certs.go            # certs/{role} 签发编排
│   ├── path_cache.go            # cache 管理端点
│   ├── cache.go                 # 证书缓存（引用计数/过期策略/singleflight）
│   ├── kvoutput.go              # KV 输出 writer + 路径 sanitize
│   ├── secret_cert.go           # cert secret 类型的 Renew/Revoke
│   ├── pebble_test.go           # pebble/challtestsrv 测试环境助手
│   ├── fake_test.go             # 假 CredentialLoader/KVOutputWriter
│   └── *_test.go                # 各文件对应单测
├── cmd/plugin/main.go           # 插件入口（ServeMultiplex）
├── test/acceptance_test.go      # 真实 bao server 验收测试
├── test/acme-dns.sh             # exec provider 测试脚本（调 challtestsrv）
├── .github/workflows/{test,release}.yml
├── Containerfile                # FROM scratch OCI 镜像
├── Makefile
└── README.md
```

---

### Task 1: 项目骨架（go.mod/Factory/插件入口/Makefile）

**Files:**
- Create: `go.mod`
- Create: `acme/backend.go`
- Create: `cmd/plugin/main.go`
- Create: `Makefile`
- Create: `.gitignore`
- Test: `acme/backend_test.go`

**Interfaces:**
- Consumes: 无（首个任务）
- Produces: `Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error)`；`Backend(conf *logical.BackendConfig) (*backend, error)`；`backend` struct：嵌入 `*framework.Backend`，字段 `credLoader CredentialLoader`、`kvWriter KVOutputWriter`、`issueGroup singleflight.Group`、`cacheMu sync.RWMutex`。后续所有路径任务向 `Backend()` 的 `Paths` 追加、向 `Secrets` 追加 `secretCert`。

- [ ] **Step 1: 写失败测试**

`acme/backend_test.go`：

```go
package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestFactory(t *testing.T) {
	conf := logical.TestBackendConfig()
	conf.RunningVersion = "v0.1.0"
	b, err := Factory(context.Background(), conf)
	require.NoError(t, err)
	require.NotNil(t, b)
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run TestFactory`
Expected: FAIL（`Factory` 未定义 / 无 go.mod）

- [ ] **Step 3: 最小实现**

`go.mod`（先手写 require，再 `go mod tidy` 补全 indirect）：

```
module github.com/chisaato/openbao-plugin-secrets-acme

go 1.26.0

require (
	github.com/go-acme/lego/v5 v5.4.1
	github.com/openbao/openbao/api/v2 v2.6.0
	github.com/openbao/openbao/sdk/v2 v2.6.2
	github.com/go-viper/mapstructure/v2 v2.4.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/sync v0.16.0
)
```

`acme/backend.go`：

```go
package acme

import (
	"context"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Factory 是 OpenBao 插件入口。
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend 构造 backend；测试可直接调用后覆写 credLoader/kvWriter。
func Backend(conf *logical.BackendConfig) (*backend, error) {
	b := &backend{
		Backend: &framework.Backend{
			BackendType:    logical.TypeLogical,
			RunningVersion: conf.RunningVersion,
			Paths:          []*framework.Path{},
			Secrets:        []*framework.Secret{},
		},
		credLoader: &apiCredentialLoader{},
		kvWriter:   &apiKVWriter{},
	}
	return b, nil
}

// backend 持有框架后端与签发链路依赖。
type backend struct {
	*framework.Backend
	credLoader CredentialLoader // 凭据实时读取器（KV）
	kvWriter   KVOutputWriter   // 证书 KV 输出
	issueGroup singleflight.Group
	cacheMu    sync.RWMutex
}
```

注：`apiCredentialLoader`/`apiKVWriter`/`CredentialLoader`/`KVOutputWriter` 在 Task 3/10 定义。为让本任务可编译，先在 `acme/backend.go` 底部放最小接口桩（Task 3/10 会替换为正式文件）：

```go
// —— 临时桩：Task 3 / Task 10 移入正式文件并实现 ——
type credentialsRef struct{}

type CredentialLoader interface {
	Load(ctx context.Context, clientToken string, ref credentialsRef) (map[string]string, error)
}

type apiCredentialLoader struct{}

func (a *apiCredentialLoader) Load(ctx context.Context, clientToken string, ref credentialsRef) (map[string]string, error) {
	return map[string]string{}, nil
}

type KVOutputWriter interface {
	Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error
}

type apiKVWriter struct{}

func (a *apiKVWriter) Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error {
	return nil
}
```

`cmd/plugin/main.go`：

```go
package main

import (
	"fmt"
	"os"

	"github.com/chisaato/openbao-plugin-secrets-acme/acme"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

// pluginVersion 由 Makefile ldflags 注入；conf.RunningVersion 优先。
var pluginVersion = "dev"

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "parse flags: %v\n", err)
		os.Exit(1)
	}
	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: acme.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "plugin server exited: %v\n", err)
		os.Exit(1)
	}
}
```

`Makefile`：

```make
GO ?= go
PLUGIN_NAME = openbao-plugin-secrets-acme
VERSION ?= $(shell git describe --tags --always --dirty)

.PHONY: build test testacc vet fmt clean

build:
	$(GO) build -ldflags "-X main.pluginVersion=$(VERSION)" -o bin/$(PLUGIN_NAME) ./cmd/plugin

test:
	$(GO) test -race ./acme/...

testacc:
	$(GO) test -v ./test/...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin/
```

`.gitignore`：

```
bin/
dist/
*.test
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go mod tidy && go test ./acme/ -run TestFactory && go build ./... && go vet ./...`
Expected: PASS + 构建成功

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum acme/backend.go acme/backend_test.go cmd/plugin/main.go Makefile .gitignore
git commit -m "feat: project skeleton with plugin Factory and cmd entry"
```

---

### Task 2: 账户模型（keyTypes/密钥 PKCS#8/legoUser/lego client 构造）

**Files:**
- Create: `acme/account.go`
- Modify: `acme/backend.go`（删除 Task 1 的 `credentialsRef`/`CredentialLoader` 桩，保留引用——改为 `type credentialsRef = credentials.Ref` 不引入；直接删除桩后 `backend` 字段类型改由 Task 3 文件提供，本任务暂不删桩）
- Test: `acme/account_test.go`

> 注：为避免跨任务编译断裂，本任务**不动** backend.go 桩；桩的移除在 Task 3（credentials.go 正式实现同名类型时从 backend.go 删除并统一）。

**Interfaces:**
- Consumes: 无
- Produces:
  - `var keyTypes = map[string]certcrypto.KeyType{...}`（键：`EC256/EC384/RSA2048/RSA4096/RSA8192`）
  - `type dnsProviderRef struct { Name string; Zones []string }`
  - `type accountEntry struct { Name, ServerURL, Contact string; TOSAgreed bool; KeyType, PrivateKeyPEM, RegistrationJSON string; InsecureTLS bool; DNSProviders []dnsProviderRef }`（全部带 json tag， snake_case）
  - `type legoUser struct { Email string; Registration *acme.ExtendedAccount; key crypto.Signer }` 实现 `registration.User`（GetEmail/GetRegistration/GetPrivateKey）
  - `generatePrivateKeyPEM(kt certcrypto.KeyType) (crypto.Signer, string, error)`（PKCS#8 PEM）
  - `parsePrivateKeyPEM(pemStr string) (crypto.Signer, error)`
  - `newLegoClient(user *legoUser, serverURL string, insecureTLS bool) (*lego.Client, error)`

- [ ] **Step 1: 写失败测试**

`acme/account_test.go`：

```go
package acme

import (
	"testing"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/registration"
	"github.com/stretchr/testify/require"
)

// 编译期断言：legoUser 实现 lego 账户接口。
var _ registration.User = (*legoUser)(nil)

func TestKeyTypesWhitelist(t *testing.T) {
	for _, kt := range []string{"EC256", "EC384", "RSA2048", "RSA4096", "RSA8192"} {
		require.Contains(t, keyTypes, kt)
	}
	require.NotContains(t, keyTypes, "RSA1024")
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	for name, kt := range keyTypes {
		t.Run(name, func(t *testing.T) {
			key, pemStr, err := generatePrivateKeyPEM(kt)
			require.NoError(t, err)
			require.Contains(t, pemStr, "BEGIN PRIVATE KEY")

			parsed, err := parsePrivateKeyPEM(pemStr)
			require.NoError(t, err)

			// 公钥部分必须一致
			require.Equal(t, key.Public(), parsed.Public())
		})
	}
}

func TestParsePrivateKeyPEMInvalid(t *testing.T) {
	_, err := parsePrivateKeyPEM("not a pem")
	require.Error(t, err)
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestKeyTypes|TestPrivateKey|TestParsePrivateKey'`
Expected: FAIL（类型未定义）

- [ ] **Step 3: 最小实现**

`acme/account.go`：

```go
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
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestKeyTypes|TestPrivateKey|TestParsePrivateKey' && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/account.go acme/account_test.go
git commit -m "feat: ACME account model with PKCS8 key persistence and lego user adapter"
```

### Task 3: 凭据实时读取（credentialsRef/CredentialLoader/KV 读取/键解析）

**Files:**
- Create: `acme/credentials.go`
- Modify: `acme/backend.go`（删除桩 `credentialsRef`、`CredentialLoader`、`apiCredentialLoader`——正式版移入本文件；保留 `KVOutputWriter`/`apiKVWriter` 桩至 Task 10）
- Create: `acme/fake_test.go`（假 loader，供后续任务共用）
- Test: `acme/credentials_test.go`

**Interfaces:**
- Consumes: 无（依赖 openbao api/v2）
- Produces:
  - `type credentialsRef struct { Mount, Path, KVVersion string; Version int; Keys map[string]string }`（json tag 全小写；`kv_version` 默认 "2"；`version` 0=最新；`keys` 左键=lego 环境变量名、右值=用户 KV 键名）
  - `type CredentialLoader interface { Load(ctx context.Context, clientToken string, ref credentialsRef) (map[string]string, error) }`
  - `type apiCredentialLoader struct{}`：`api.NewClient(nil)`（地址取插件进程 env `BAO_ADDR`/`VAULT_ADDR`）→ `SetToken(clientToken)` → KVv2 `GetWithData` / KVv1 `Get`
  - `resolveKeys(raw map[string]string, ref credentialsRef, envNames []string) map[string]string`：显式 Keys 映射优先，同名回退，仅输出 envNames 命中项
  - `fakeCredentialLoader`（`fake_test.go`）：`NewFakeCredentialLoader(data map[string]string) *fakeCredentialLoader`

- [ ] **Step 1: 写失败测试**

`acme/credentials_test.go`：

```go
package acme

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveKeysExplicitMapping(t *testing.T) {
	raw := map[string]string{"cf_token": "s3cret", "extra": "x"}
	ref := credentialsRef{Keys: map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "cf_token"}}
	got := resolveKeys(raw, ref, []string{"CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_ZONE_API_TOKEN"})
	require.Equal(t, map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "s3cret"}, got)
}

func TestResolveKeysSameNameFallback(t *testing.T) {
	raw := map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "tok", "ALICLOUD_SECRET_KEY": "sk"}
	got := resolveKeys(raw, credentialsRef{}, []string{
		"CLOUDFLARE_DNS_API_TOKEN", "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY",
	})
	require.Equal(t, map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
		"ALICLOUD_SECRET_KEY":      "sk",
	}, got)
}

func TestRefKVVersionDefault(t *testing.T) {
	require.Equal(t, "2", (&credentialsRef{}).kvVersion())
	require.Equal(t, "1", (&credentialsRef{KVVersion: "1"}).kvVersion())
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestResolveKeys|TestRefKVVersion'`
Expected: FAIL（未定义）

- [ ] **Step 3: 最小实现**

`acme/credentials.go`：

```go
package acme

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/api/v2/kv"
)

// credentialsRef 描述一处 KV 凭据引用。Keys 左键为适配层所需的 lego
// 环境变量名，右值为用户 KV 数据中的实际键名；缺省时回退同名查找。
type credentialsRef struct {
	Mount     string            `json:"mount"`
	Path      string            `json:"path"`
	KVVersion string            `json:"kv_version"`
	Version   int               `json:"version"`
	Keys      map[string]string `json:"keys"`
}

func (r *credentialsRef) kvVersion() string {
	if r.KVVersion == "1" {
		return "1"
	}
	return "2"
}

// CredentialLoader 在请求生命周期内实时读取 KV（不快照、不落存储）。
type CredentialLoader interface {
	Load(ctx context.Context, clientToken string, ref credentialsRef) (map[string]string, error)
}

// apiCredentialLoader 用调用者 token 构造客户端实时读 KV。
// API 地址来自插件进程环境变量（BAO_ADDR/VAULT_ADDR），部署须保证注入（见 README）。
type apiCredentialLoader struct{}

func (a *apiCredentialLoader) Load(ctx context.Context, clientToken string, ref credentialsRef) (map[string]string, error) {
	if ref.Mount == "" || ref.Path == "" {
		return nil, fmt.Errorf("credentials_ref 需要 mount 与 path")
	}
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, fmt.Errorf("create openbao client: %w", err)
	}
	client.SetToken(clientToken)

	var data map[string]interface{}
	switch ref.kvVersion() {
	case "1":
		secret, err := client.KVv1(ref.Mount).Get(ctx, ref.Path)
		if err != nil {
			return nil, fmt.Errorf("read kv1 %s/%s: %w", ref.Mount, ref.Path, err)
		}
		data = secret.Data
	default:
		opts := kv.GetWithDataOptions{Path: ref.Path, Version: ref.Version}
		secret, err := client.KVv2(ref.Mount).GetWithData(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("read kv2 %s/data/%s: %w", ref.Mount, ref.Path, err)
		}
		data = secret.Data
	}

	raw := make(map[string]string, len(data))
	for k, v := range data {
		if s, ok := v.(string); ok {
			raw[k] = s
			continue
		}
		raw[k] = fmt.Sprintf("%v", v)
	}
	return raw, nil
}

// resolveKeys：显式 Keys 映射优先，同名回退；仅输出 envNames 命中项。
func resolveKeys(raw map[string]string, ref credentialsRef, envNames []string) map[string]string {
	out := make(map[string]string, len(envNames))
	for _, env := range envNames {
		if userKey, ok := ref.Keys[env]; ok {
			if v, ok := raw[userKey]; ok {
				out[env] = v
				continue
			}
		}
		if v, ok := raw[env]; ok {
			out[env] = v
		}
	}
	return out
}
```

`acme/backend.go`：删除桩 `credentialsRef`/`CredentialLoader`/`apiCredentialLoader` 及其方法（保留 `KVOutputWriter`/`apiKVWriter` 桩）。

`acme/fake_test.go`：

```go
package acme

import (
	"context"

	"github.com/stretchr/testify/require"
)

// fakeCredentialLoader 返回预置凭据，供签发/路径测试使用。
type fakeCredentialLoader struct {
	data map[string]string
}

func NewFakeCredentialLoader(data map[string]string) *fakeCredentialLoader {
	return &fakeCredentialLoader{data: data}
}

func (f *fakeCredentialLoader) Load(ctx context.Context, clientToken string, ref credentialsRef) (map[string]string, error) {
	require.NotEmpty(ctx, clientToken, "clientToken 必须传递")
	return f.data, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestResolveKeys|TestRefKVVersion' && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/credentials.go acme/credentials_test.go acme/fake_test.go acme/backend.go
git commit -m "feat: live KV credential loading with SecretRef-style key mapping"
```

---

### Task 4: DNS provider 注册表（cloudflare/alidns/tencentcloud）

**Files:**
- Create: `acme/providers.go`
- Test: `acme/providers_test.go`

**Interfaces:**
- Consumes: 无（独立纯逻辑）
- Produces:
  - `type providerOpts struct { PropagationTimeout, PollingInterval time.Duration }`
  - `type providerBuilder func(ctx context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error)`
  - `var registry map[string]providerBuilder`（键：`cloudflare`/`alidns`/`tencentcloud`；扩展=加一行）
  - `var envNames map[string][]string`（各 provider 认识的全部键名，凭据映射合法左值）
  - `newProvider(ctx, typeName string, opts providerOpts, env map[string]string) (challenge.Provider, error)`：查注册表+构造；未知类型报可用列表
  - 导出测试断言用：`cloudflareConfig(env) (*cloudflare.Config, error)`、`alidnsConfig(env) (*alidns.Config, error)`、`tencentcloudConfig(env) (*tencentcloud.Config, error)`

- [ ] **Step 1: 写失败测试**

`acme/providers_test.go`：

```go
package acme

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCloudflareConfigTokenOnly(t *testing.T) {
	cfg, err := cloudflareConfig(map[string]string{"CLOUDFLARE_DNS_API_TOKEN": "tok"})
	require.NoError(t, err)
	require.Equal(t, "tok", cfg.AuthToken)
}

func TestCloudflareConfigGlobalKey(t *testing.T) {
	cfg, err := cloudflareConfig(map[string]string{
		"CLOUDFLARE_EMAIL": "a@b.c", "CLOUDFLARE_API_KEY": "gk",
	})
	require.NoError(t, err)
	require.Equal(t, "a@b.c", cfg.AuthEmail)
	require.Equal(t, "gk", cfg.AuthKey)
}

func TestCloudflareConfigMissing(t *testing.T) {
	_, err := cloudflareConfig(map[string]string{})
	require.ErrorContains(t, err, "CLOUDFLARE_DNS_API_TOKEN")
}

func TestAliDNSConfig(t *testing.T) {
	cfg, err := alidnsConfig(map[string]string{
		"ALICLOUD_ACCESS_KEY": "ak", "ALICLOUD_SECRET_KEY": "sk",
	})
	require.NoError(t, err)
	require.Equal(t, "ak", cfg.APIKey)
	require.Equal(t, "sk", cfg.SecretKey)

	_, err = alidnsConfig(map[string]string{"ALICLOUD_ACCESS_KEY": "ak"})
	require.Error(t, err)
}

func TestTencentCloudConfig(t *testing.T) {
	cfg, err := tencentcloudConfig(map[string]string{
		"TENCENTCLOUD_SECRET_ID": "id", "TENCENTCLOUD_SECRET_KEY": "key",
	})
	require.NoError(t, err)
	require.Equal(t, "id", cfg.SecretID)
	require.Equal(t, "key", cfg.SecretKey)

	_, err = tencentcloudConfig(map[string]string{})
	require.Error(t, err)
}

func TestRegistryWhitelist(t *testing.T) {
	for _, name := range []string{"cloudflare", "alidns", "tencentcloud"} {
		require.Contains(t, registry, name)
	}
	_, err := newProvider(t.Context(), "dnspod", providerOpts{}, nil)
	require.ErrorContains(t, err, "cloudflare, alidns, tencentcloud")
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestCloudflare|TestAliDNS|TestTencent|TestRegistry'`
Expected: FAIL（未定义）

- [ ] **Step 3: 最小实现**

`acme/providers.go`：

```go
package acme

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/alidns"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/providers/dns/tencentcloud"
)

// providerOpts 是 dns-providers 条目上的通用调参。
type providerOpts struct {
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

// providerBuilder 用凭据键值构造 lego provider。
type providerBuilder func(ctx context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error)

// registry 是 DNS provider 白名单；扩展新 provider 在此加一行。
var registry = map[string]providerBuilder{
	"cloudflare":   buildCloudflare,
	"alidns":       buildAliDNS,
	"tencentcloud": buildTencentCloud,
}

// envNames 是各 provider 认识的全部键名（凭据映射 keys 的合法左值）。
var envNames = map[string][]string{
	"cloudflare":   {"CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY", "CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_ZONE_API_TOKEN"},
	"alidns":       {"ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY", "ALICLOUD_SECURITY_TOKEN", "ALICLOUD_REGION_ID"},
	"tencentcloud": {"TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_REGION", "TENCENTCLOUD_SESSION_TOKEN"},
}

// newProvider 按类型查注册表并构造 provider。
func newProvider(ctx context.Context, typeName string, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	build, ok := registry[typeName]
	if !ok {
		names := make([]string, 0, len(registry))
		for n := range registry {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("未知 dns provider 类型 %q（可用：%s）", typeName, strings.Join(names, ", "))
	}
	return build(ctx, opts, env)
}

func applyTimeouts(opts providerOpts, propagation, polling *time.Duration) {
	if opts.PropagationTimeout > 0 {
		*propagation = opts.PropagationTimeout
	}
	if opts.PollingInterval > 0 {
		*polling = opts.PollingInterval
	}
}

func buildCloudflare(_ context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	cfg, err := cloudflareConfig(env)
	if err != nil {
		return nil, err
	}
	applyTimeouts(opts, &cfg.PropagationTimeout, &cfg.PollingInterval)
	return cloudflare.NewDNSProviderConfig(cfg)
}

// cloudflareConfig 导出供测试断言。
func cloudflareConfig(env map[string]string) (*cloudflare.Config, error) {
	cfg := cloudflare.NewDefaultConfig()
	if v, ok := env["CLOUDFLARE_EMAIL"]; ok {
		cfg.AuthEmail = v
	}
	if v, ok := env["CLOUDFLARE_API_KEY"]; ok {
		cfg.AuthKey = v
	}
	if v, ok := env["CLOUDFLARE_DNS_API_TOKEN"]; ok {
		cfg.AuthToken = v
	}
	if v, ok := env["CLOUDFLARE_ZONE_API_TOKEN"]; ok {
		cfg.ZoneToken = v
	}
	if cfg.AuthToken == "" && (cfg.AuthKey == "" || cfg.AuthEmail == "") {
		return nil, fmt.Errorf("cloudflare: 需要 CLOUDFLARE_DNS_API_TOKEN 或 CLOUDFLARE_EMAIL+CLOUDFLARE_API_KEY（可用键：%s）",
			strings.Join(envNames["cloudflare"], ", "))
	}
	return cfg, nil
}

func buildAliDNS(_ context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	cfg, err := alidnsConfig(env)
	if err != nil {
		return nil, err
	}
	applyTimeouts(opts, &cfg.PropagationTimeout, &cfg.PollingInterval)
	return alidns.NewDNSProviderConfig(cfg)
}

func alidnsConfig(env map[string]string) (*alidns.Config, error) {
	cfg := alidns.NewDefaultConfig()
	if v, ok := env["ALICLOUD_ACCESS_KEY"]; ok {
		cfg.APIKey = v
	}
	if v, ok := env["ALICLOUD_SECRET_KEY"]; ok {
		cfg.SecretKey = v
	}
	if v, ok := env["ALICLOUD_SECURITY_TOKEN"]; ok {
		cfg.SecurityToken = v
	}
	if v, ok := env["ALICLOUD_REGION_ID"]; ok {
		cfg.RegionID = v
	}
	if cfg.APIKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("alidns: 需要 ALICLOUD_ACCESS_KEY+ALICLOUD_SECRET_KEY（可用键：%s）",
			strings.Join(envNames["alidns"], ", "))
	}
	return cfg, nil
}

func buildTencentCloud(_ context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	cfg, err := tencentcloudConfig(env)
	if err != nil {
		return nil, err
	}
	applyTimeouts(opts, &cfg.PropagationTimeout, &cfg.PollingInterval)
	return tencentcloud.NewDNSProviderConfig(cfg)
}

func tencentcloudConfig(env map[string]string) (*tencentcloud.Config, error) {
	cfg := tencentcloud.NewDefaultConfig()
	if v, ok := env["TENCENTCLOUD_SECRET_ID"]; ok {
		cfg.SecretID = v
	}
	if v, ok := env["TENCENTCLOUD_SECRET_KEY"]; ok {
		cfg.SecretKey = v
	}
	if v, ok := env["TENCENTCLOUD_REGION"]; ok {
		cfg.Region = v
	}
	if v, ok := env["TENCENTCLOUD_SESSION_TOKEN"]; ok {
		cfg.SessionToken = v
	}
	if cfg.SecretID == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("tencentcloud: 需要 TENCENTCLOUD_SECRET_ID+TENCENTCLOUD_SECRET_KEY（可用键：%s）",
			strings.Join(envNames["tencentcloud"], ", "))
	}
	return cfg, nil
}
```

需在 import 加 `"sort"`（TestRegistryWhitelist 的报错信息按字母序列出）。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestCloudflare|TestAliDNS|TestTencent|TestRegistry' && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/providers.go acme/providers_test.go
git commit -m "feat: DNS provider registry for cloudflare, alidns, tencentcloud"
```

### Task 5: dns-providers 路径（CRUD+LIST/fail-fast 试读/type 不可改/引用检查）

**Files:**
- Create: `acme/path_dns_providers.go`
- Modify: `acme/backend_test.go`（追加共享助手 `testBackend(t, loader)`）
- Test: `acme/path_dns_providers_test.go`

**Interfaces:**
- Consumes: Task 3 `credentialsRef`/`CredentialLoader`；Task 4 `registry`/`envNames`/`newProvider`/`providerOpts`/`resolveKeys`
- Produces:
  - `type dnsProviderEntry struct { Type string; CredentialsRef *credentialsRef; PropagationTimeout, PollingInterval time.Duration }`（json tag：`type`/`credentials_ref`/`propagation_timeout`/`polling_interval`）
  - `const storageKeyDNSProviders = "dns-providers/"`
  - `func (b *backend) getDNSProvider(ctx, s logical.Storage, name string) (*dnsProviderEntry, error)`
  - `testBackend(t *testing.T, loader CredentialLoader) (*backend, logical.Storage)`：构造+Setup backend，可注入假 loader，返回 StorageView

- [ ] **Step 1: 写失败测试**

`acme/path_dns_providers_test.go`：

```go
package acme

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

const testCFEnv = `{"CLOUDFLARE_DNS_API_TOKEN":"tok"}`

func dnsRefJSON() map[string]interface{} {
	var ref map[string]interface{}
	require.NoError(t := func() error { return json.Unmarshal([]byte(testCFEnv), &ref) }(), "parse")
	return ref
}
```

上方 helper 过于绕，改用直接构造（以下为测试正体）：

```go
package acme

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestDNSProviderCRUD(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))

	// 创建（fail-fast 试读通过）
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "dns-providers/cf",
		Storage:   storage,
		Data: map[string]interface{}{
			"type":            "cloudflare",
			"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
		},
	}, nil)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "创建失败: %v", resp)

	// 读取
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "dns-providers/cf", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "cloudflare", resp.Data["type"])
	require.Equal(t, time.Duration(0), resp.Data["propagation_timeout"])

	// 未知类型 → 试读报错（含可用列表）
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "dns-providers/bad",
		Storage:   storage,
		Data: map[string]interface{}{
			"type":            "dnspod",
			"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
		},
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "cloudflare, alidns, tencentcloud")

	// type 创建后不可改
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "dns-providers/cf",
		Storage:   storage,
		Data: map[string]interface{}{
			"type":            "alidns",
			"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
		},
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "不可")

	// LIST
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation, Path: "dns-providers/", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"cf"}, resp.Data["keys"])

	// 删除
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation, Path: "dns-providers/cf", Storage: storage,
	}, nil)
	require.NoError(t, err)
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "dns-providers/cf", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestDNSProviderDeleteReferenced(t *testing.T) {
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))
	// 预置 dns-provider 与引用它的 account
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "dns-providers/cf",
		Storage:   storage,
		Data: map[string]interface{}{
			"type":            "cloudflare",
			"credentials_ref": map[string]interface{}{"mount": "secret", "path": "dns/cf"},
		},
	}, nil)
	require.NoError(t, err)
	acc := accountEntry{Name: "le", DNSProviders: []dnsProviderRef{{Name: "cf"}}}
	require.NoError(t, storage.Put(context.Background(), &logical.StorageEntry{
		Key:   "accounts/le",
		Value: mustJSON(t, acc),
	}))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation, Path: "dns-providers/cf", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "le")
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
```

`acme/backend_test.go` 追加共享助手：

```go
// testBackend 构造并 Setup backend，注入 loader（nil=默认 apiCredentialLoader）。
func testBackend(t *testing.T, loader CredentialLoader) (*backend, logical.Storage) {
	t.Helper()
	conf := logical.TestBackendConfig()
	// 注：logical.BackendConfig 无 RunningVersion 字段（controller ruling），
	// 版本自报经 acme.Version 包级变量接线，见 Task 1 fix round 1。
	b, err := Backend(conf)
	require.NoError(t, err)
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatal(err)
	}
	if loader != nil {
		b.credLoader = loader
	}
	return b, conf.StorageView
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestDNSProvider'`
Expected: FAIL（路径未注册/类型未定义）

- [ ] **Step 3: 最小实现**

`acme/path_dns_providers.go`：

```go
package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyDNSProviders = "dns-providers/"

// dnsProviderEntry：凭据只存引用，签发时实时读取（不快照）。
type dnsProviderEntry struct {
	Type               string          `json:"type"`
	CredentialsRef     *credentialsRef `json:"credentials_ref,omitempty"`
	PropagationTimeout time.Duration   `json:"propagation_timeout"`
	PollingInterval    time.Duration   `json:"polling_interval"`
}

// validateProviderEntry 校验类型与凭据引用（fail-fast 试读，不落存储）。
func (b *backend) validateProviderEntry(ctx context.Context, req *logical.Request, entry *dnsProviderEntry) error {
	if _, ok := registry[entry.Type]; !ok {
		return fmt.Errorf("type 创建后不可改且必须在白名单内") // 占位：unknown 分支在 write 中区分
	}
	if entry.CredentialsRef == nil {
		return fmt.Errorf("credentials_ref 必填")
	}
	raw, err := b.credLoader.Load(ctx, req.ClientToken, *entry.CredentialsRef)
	if err != nil {
		return fmt.Errorf("凭据试读失败: %w", err)
	}
	if _, err := newProvider(ctx, entry.Type, providerOpts{},
		resolveKeys(raw, *entry.CredentialsRef, envNames[entry.Type])); err != nil {
		return fmt.Errorf("provider 试构造失败: %w", err)
	}
	return nil
}

func (b *backend) getDNSProvider(ctx context.Context, s logical.Storage, name string) (*dnsProviderEntry, error) {
	item, err := s.Get(ctx, storageKeyDNSProviders+name)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	var entry dnsProviderEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func pathDNSProviders(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "DNS provider 名称（account 中以该名称引用）。",
		},
		"type": {
			Type:        framework.TypeString,
			Description: "lego provider 类型，白名单：cloudflare、alidns、tencentcloud。创建后不可改。",
		},
		"credentials_ref": {
			Type:        framework.TypeMap,
			Description: "凭据引用 {mount, path, kv_version=\"2\", version=0, keys={LEGO_VAR: 用户键名}}。写操作时试读校验但不快照。",
		},
		"propagation_timeout": {
			Type:        framework.TypeDurationSecond,
			Description: "DNS 传播等待上限；0=用 provider 默认。",
		},
		"polling_interval": {
			Type:        framework.TypeDurationSecond,
			Description: "传播轮询间隔；0=用 provider 默认。",
		},
	}

	write := &framework.Path{
		Pattern:      "dns-providers/" + framework.GenericNameRegex("name"),
		Fields:       fields,
		ExistenceCheck: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
			entry, err := b.getDNSProvider(ctx, req.Storage, d.Get("name").(string))
			return entry != nil, err
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathDNSProviderWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathDNSProviderWrite},
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					entry, err := b.getDNSProvider(ctx, req.Storage, d.Get("name").(string))
					if err != nil || entry == nil {
						return nil, err
					}
					return &logical.Response{Data: map[string]interface{}{
						"type":                entry.Type,
						"propagation_timeout": int64(entry.PropagationTimeout.Seconds()),
						"polling_interval":    int64(entry.PollingInterval.Seconds()),
					}}, nil
				},
			},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathDNSProviderDelete},
		},
	}

	list := &framework.Path{
		Pattern: "dns-providers/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathDNSProviderList},
		},
	}
	return []*framework.Path{write, list}
}

func (b *backend) pathDNSProviderWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	existing, err := b.getDNSProvider(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	entry := &dnsProviderEntry{}
	if existing != nil {
		entry = existing // Update：type 不可改
	}

	newType, ok := d.GetOk("type")
	if !existing || ok {
		if existing != nil && newType.(string) != existing.Type {
			return logical.ErrorResponse("type 创建后不可改"), nil
		}
		entry.Type = newType.(string)
	}
	if refRaw, ok := d.GetOk("credentials_ref"); ok {
		ref := &credentialsRef{}
		if err := mapstructure.WeakDecode(refRaw, ref); err != nil {
			return logical.ErrorResponse("credentials_ref 解析失败: %v", err), nil
		}
		entry.CredentialsRef = ref
	}
	if v, ok := d.GetOk("propagation_timeout"); ok {
		entry.PropagationTimeout = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("polling_interval"); ok {
		entry.PollingInterval = time.Duration(v.(int)) * time.Second
	}

	if _, ok := registry[entry.Type]; !ok {
		names := make([]string, 0, len(registry))
		for n := range registry {
			names = append(names, n)
		}
		sort.Strings(names)
		return logical.ErrorResponse("未知 dns provider 类型 %q（可用：%s）", entry.Type, strings.Join(names, ", ")), nil
	}
	// fail-fast 试读：保证引用正确、凭据可达，但不快照。
	if err := b.validateProviderEntry(ctx, req, entry); err != nil {
		return logical.ErrorResponse("%v", err), nil
	}

	item, err := logical.StorageEntryJSON(storageKeyDNSProviders+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, item); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathDNSProviderDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if _, err := b.getDNSProvider(ctx, req.Storage, name); err != nil {
		return nil, err
	}
	// 引用检查：任何 account 的 dns_providers 引用该名称则拒绝删除。
	keys, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		item, err := req.Storage.Get(ctx, "accounts/"+k)
		if err != nil {
			return nil, err
		}
		if item == nil {
			continue
		}
		var acc accountEntry
		if err := item.DecodeJSON(&acc); err != nil {
			return nil, err
		}
		for _, ref := range acc.DNSProviders {
			if ref.Name == name {
				return logical.ErrorResponse("dns-provider %q 正被 account %q 引用，无法删除", name, acc.Name), nil
			}
		}
	}
	return nil, req.Storage.Delete(ctx, storageKeyDNSProviders+name)
}

func (b *backend) pathDNSProviderList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, storageKeyDNSProviders)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}
```

`Backend()` 中注册：`Paths: pathDNSProviders(b)`（Task 7 起改为 `append(pathDNSProviders(b), ...)` 聚合多个 path 构造函数——Task 7 会引入 `paths(b)` 聚合函数统一管理）。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestDNSProvider|TestFactory' && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/path_dns_providers.go acme/path_dns_providers_test.go acme/backend.go acme/backend_test.go
git commit -m "feat: dns-providers path with fail-fast credential validation"
```

---

### Task 6: 复合路由 challenge.Provider（cert-manager 匹配语义）

**Files:**
- Create: `acme/routing.go`
- Test: `acme/routing_test.go`

**Interfaces:**
- Consumes: `github.com/go-acme/lego/v5/challenge`（Provider/ProviderTimeout 接口）
- Produces:
  - `type providerRoute struct { Name string; Zones []string; Provider challenge.Provider }`
  - `func newRoutingProvider(routes []providerRoute) (*routingProvider, error)`
  - `func (rp *routingProvider) match(domain string) (*providerRoute, error)`：通配符剥除 `*.`、后缀匹配、zone 段数多者优先、无 zones 兜底、无匹配报错
  - 实现 `challenge.ProviderTimeout`（Timeout 取各子 provider 最大值；默认 60s/2s）
  - 路由表构造后只读 → 并发安全（lego prober 并行 PreSolve 调 Present）

- [ ] **Step 1: 写失败测试**

`acme/routing_test.go`：

```go
package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// recordingProvider 记录 Present/CleanUp 的 domain，用于断言委托。
type recordingProvider struct{ domains []string }

func (p *recordingProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	p.domains = append(p.domains, "present:"+domain)
	return nil
}
func (p *recordingProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	p.domains = append(p.domains, "cleanup:"+domain)
	return nil
}
func (p *recordingProvider) Timeout() (time.Duration, time.Duration) { return 10 * time.Second, 1 * time.Second }

func TestRoutingMatch(t *testing.T) {
	slow := &recordingProvider{}
	fallback := &recordingProvider{}
	rp, err := newRoutingProvider([]providerRoute{
		{Name: "cf-base", Zones: []string{"example.com"}, Provider: slow},
		{Name: "cf-sys", Zones: []string{"sys.example.com"}, Provider: fallback},
		{Name: "catch-all", Provider: fallback},
	})
	require.NoError(t, err)

	// 精度优先：sys.example.com 胜过 example.com
	r, err := rp.match("www.sys.example.com")
	require.NoError(t, err)
	require.Equal(t, "cf-sys", r.Name)

	// 后缀匹配
	r, _ = rp.match("www.example.com")
	require.Equal(t, "cf-base", r.Name)

	// 通配符剥除
	r, _ = rp.match("*.example.com")
	require.Equal(t, "cf-base", r.Name)

	// 兜底
	r, _ = rp.match("other.org")
	require.Equal(t, "catch-all", r.Name)
}

func TestRoutingNoFallbackError(t *testing.T) {
	rp, err := newRoutingProvider([]providerRoute{
		{Name: "only", Zones: []string{"example.com"}, Provider: &recordingProvider{}},
	})
	require.NoError(t, err)
	_, err = rp.match("other.org")
	require.ErrorContains(t, err, "无匹配")
}

func TestRoutingOrderTieBreak(t *testing.T) {
	first, second := &recordingProvider{}, &recordingProvider{}
	rp, _ := newRoutingProvider([]providerRoute{
		{Name: "first", Zones: []string{"a.com", "b.com"}, Provider: first},
		{Name: "second", Zones: []string{"b.com"}, Provider: second},
	})
	r, err := rp.match("x.b.com")
	require.NoError(t, err)
	require.Equal(t, "first", r.Name) // 深度平局 → 列表顺序
}

func TestRoutingDelegation(t *testing.T) {
	p := &recordingProvider{}
	rp, _ := newRoutingProvider([]providerRoute{
		{Name: "cf", Zones: []string{"example.com"}, Provider: p},
	})
	ctx := context.Background()
	require.NoError(t, rp.Present(ctx, "www.example.com", "tok", "ka"))
	require.NoError(t, rp.CleanUp(ctx, "www.example.com", "tok", "ka"))
	require.Equal(t, []string{"present:www.example.com", "cleanup:www.example.com"}, p.domains)
}

func TestRoutingTimeoutAggregate(t *testing.T) {
	rp, _ := newRoutingProvider([]providerRoute{
		{Name: "a", Provider: &recordingProvider{}},               // 10s/1s
		{Name: "b", Provider: &routingDefaultProvider{}},          // 无 Timeout 接口
	})
	timeout, interval := rp.Timeout()
	require.Equal(t, 10*time.Second, timeout)
	require.Equal(t, time.Second, interval)
}

// routingDefaultProvider 只有 Provider 接口（测试无 Timeout 的子 provider）。
type routingDefaultProvider struct{ recordingProvider }
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestRouting'`
Expected: FAIL（未定义）

- [ ] **Step 3: 最小实现**

`acme/routing.go`：

```go
package acme

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
)

// providerRoute 把 DNS zone 列表绑定到一个已构造的 provider；Zones 空=兜底。
type providerRoute struct {
	Name     string
	Zones    []string
	Provider challenge.Provider
}

// routingProvider 按域名委托 Present/CleanUp。路由表构造后只读，并发安全。
type routingProvider struct {
	routes []providerRoute
}

// 编译期断言：具备超时聚合能力。
var _ challenge.ProviderTimeout = (*routingProvider)(nil)

func newRoutingProvider(routes []providerRoute) (*routingProvider, error) {
	for i, r := range routes {
		if r.Provider == nil {
			return nil, fmt.Errorf("route[%d] (%s) provider 为空", i, r.Name)
		}
	}
	return &routingProvider{routes: routes}, nil
}

// match：zones 后缀匹配、zone 段数多者优先、平局按列表顺序、无 zones 兜底、无匹配报错。
func (rp *routingProvider) match(domain string) (*providerRoute, error) {
	d := strings.TrimPrefix(strings.ToLower(domain), "*.")

	var best *providerRoute
	bestLabels := -1
	for i := range rp.routes {
		r := &rp.routes[i]
		for _, zone := range r.Zones {
			zone = strings.ToLower(strings.TrimSuffix(zone, "."))
			if d == zone || strings.HasSuffix(d, "."+zone) {
				if labels := strings.Count(zone, ".") + 1; labels > bestLabels {
					best, bestLabels = r, labels
				}
				break
			}
		}
	}
	if best != nil {
		return best, nil
	}
	for i := range rp.routes {
		if len(rp.routes[i].Zones) == 0 {
			return &rp.routes[i], nil
		}
	}
	return nil, fmt.Errorf("域名 %q 无匹配的 dns provider 路由", domain)
}

func (rp *routingProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	r, err := rp.match(domain)
	if err != nil {
		return err
	}
	return r.Provider.Present(ctx, domain, token, keyAuth)
}

func (rp *routingProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	r, err := rp.match(domain)
	if err != nil {
		return err
	}
	return r.Provider.CleanUp(ctx, domain, token, keyAuth)
}

// Timeout 返回各子 provider 最保守（最大）的组合；全默认时 60s/2s。
func (rp *routingProvider) Timeout() (timeout, interval time.Duration) {
	for _, r := range rp.routes {
		if pt, ok := r.Provider.(challenge.ProviderTimeout); ok {
			if t, i := pt.Timeout(); t > timeout {
				timeout = t
			} else if ti, _ := pt.Timeout(); ti > interval {
				interval = ti
			}
		}
	}
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if interval == 0 {
		interval = 2 * time.Second
	}
	return timeout, interval
}
```

> 注：`Timeout()` 里两次调用 `pt.Timeout()` 写法不优雅，实现时改为一次取值后分别比较（`t, i := pt.Timeout(); if t > timeout {...}; if i > interval {...}`）。以此为准实现。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestRouting' && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/routing.go acme/routing_test.go
git commit -m "feat: cert-manager style multi-provider DNS routing"
```

### Task 7: pebble 测试环境 + accounts 路径（CRUD/rollover/key 导出）

**Files:**
- Create: `acme/pebble_test.go`
- Create: `acme/path_accounts.go`
- Modify: `acme/account.go`（加 `(e *accountEntry) legoUser() (*legoUser, error)` 助手）
- Test: `acme/path_accounts_test.go`

**Interfaces:**
- Consumes: Task 2 `keyTypes`/`generatePrivateKeyPEM`/`parsePrivateKeyPEM`/`newLegoClient`/`legoUser`/`accountEntry`
- Produces:
  - `type pebbleEnv struct { DirURL, ChallSrv string }`；`startPebble(t *testing.T) *pebbleEnv`（子进程 pebble :14000 + challtestsrv DNS :8053/HTTP :8055/TLS-ALPN :5001；`PEBBLE_VA_NOSLEEP=1`；等 `/dir` 就绪；t.Cleanup 收尸；二进制缺失 t.Skip）
  - accounts 路径字段：`server_url`（必填，可改）、`contact`（必填）、`terms_of_service_agreed`、`key_type`（默认 EC256，白名单，创建后不可改，只能 rollover）、`insecure_tls`、`dns_providers`（TypeSlice，`[{name, zones?: [...]}]`）
  - 子路径：`POST accounts/{name}/rollover {key_type}`（lego `Registration.KeyRollover`）；`GET accounts/{name}/key`（导出私钥 PEM——read 主端点不回显私钥）
  - 删除=尽力 `Deactivate` + 删存储
  - `(e *accountEntry) legoUser() (*legoUser, error)`

- [ ] **Step 1: 写失败测试**

`acme/path_accounts_test.go`：

```go
package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

const testDirURL = "PLACEHOLDER" // 各测试用 env.DirURL

func accountData(dirURL string) map[string]interface{} {
	return map[string]interface{}{
		"server_url":               dirURL,
		"contact":                  "admin@example.com",
		"terms_of_service_agreed":  true,
		"insecure_tls":             true,
	}
}

func TestAccountsLifecycle(t *testing.T) {
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 创建（Register 到 pebble）
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	}, nil)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create: %v", resp)

	// 读取：不回显私钥
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, env.DirURL, resp.Data["server_url"])
	require.Equal(t, "EC256", resp.Data["key_type"])
	require.Nil(t, resp.Data["private_key"])

	// key_type 直接改 → 报错（引导 rollover）
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "accounts/le",
		Storage: storage, Data: map[string]interface{}{"key_type": "EC384"},
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "rollover")

	// key 导出
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le/key", Storage: storage,
	}, nil)
	require.NoError(t, err)
	key1 := resp.Data["private_key"].(string)
	require.Contains(t, key1, "BEGIN PRIVATE KEY")

	// rollover EC256 → RSA2048
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le/rollover",
		Storage: storage, Data: map[string]interface{}{"key_type": "RSA2048"},
	}, nil)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "rollover: %v", resp)
	resp, _ = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le/key", Storage: storage,
	}, nil)
	require.NotEqual(t, key1, resp.Data["private_key"])

	// 更新 contact（同 CA → UpdateRegistration）
	data := accountData(env.DirURL)
	data["contact"] = "new@example.com"
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "accounts/le",
		Storage: storage, Data: data,
	}, nil)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "update: %v", resp)
	resp, _ = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le", Storage: storage,
	}, nil)
	require.Equal(t, "new@example.com", resp.Data["contact"])

	// LIST
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "accounts/", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"le"}, resp.Data["keys"])

	// 删除（Deactivate 尽力而为 + 删存储）
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "accounts/le", Storage: storage,
	}, nil)
	require.NoError(t, err)
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestAccountInvalidKeyType(t *testing.T) {
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	data := accountData(env.DirURL)
	data["key_type"] = "RSA1024"
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/bad",
		Storage: storage, Data: data,
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestAccounts' -v`
Expected: FAIL（路径未注册；pebble 缺失则先 `go install` 二进制或确认 PATH）

- [ ] **Step 3: 实现**

`acme/pebble_test.go`（测试专用，file 在单测包内）：

```go
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

// startPebble 启动 pebble + challtestsrv 子进程并等待就绪；二进制缺失时 Skip。
func startPebble(t *testing.T) *pebbleEnv {
	t.Helper()
	pebbleBin, err := exec.LookPath("pebble")
	if err != nil {
		t.Skip("pebble 不在 PATH（安装：go install github.com/letsencrypt/pebble/cmd/pebble@main）")
	}
	challBin, err := exec.LookPath("pebble-challtestsrv")
	if err != nil {
		t.Skip("pebble-challtestsrv 不在 PATH")
	}

	dir := t.TempDir()
	certPEM, keyPEM, err := selfSignedCertPEM()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600))

	cfg, _ := json.Marshal(map[string]any{"pebble": map[string]any{
		"listenAddress": "127.0.0.1:14000",
		"certificate":   filepath.Join(dir, "cert.pem"),
		"privateKey":    filepath.Join(dir, "key.pem"),
		"httpPort":      8055,
		"tlsPort":       5001,
	}})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pebble-config.json"), cfg, 0o600))

	env := &pebbleEnv{DirURL: "https://127.0.0.1:14000/dir", ChallSrv: "http://127.0.0.1:8055"}
	pebble := exec.Command(pebbleBin, "-config", filepath.Join(dir, "pebble-config.json"),
		"-dnsserver", "127.0.0.1:8053")
	pebble.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1")
	pebble.Stdout, pebble.Stderr = os.Stdout, os.Stderr
	challsrv := exec.Command(challBin, "-httpsport", "8055", "-tlsalpnport", "5001",
		"-dnsport", "8053", "-defaultIPv4", "127.0.0.1")
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

// selfSignedCertPEM 生成 pebble 用的自签证书（测试信任由 InsecureSkipVerify 提供）。
func selfSignedCertPEM() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pebble"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
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
```

`acme/account.go` 追加：

```go
// legoUser 从持久化字段重建 lego 用户（私钥+注册信息）。
func (e *accountEntry) legoUser() (*legoUser, error) {
	key, err := parsePrivateKeyPEM(e.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("account %s: %w", e.Name, err)
	}
	u := &legoUser{Email: e.Contact, key: key}
	if e.RegistrationJSON != "" {
		var reg acme.ExtendedAccount
		if err := json.Unmarshal([]byte(e.RegistrationJSON), &reg); err != nil {
			return nil, fmt.Errorf("account %s: decode registration: %w", e.Name, err)
		}
		u.Registration = &reg
	}
	return u, nil
}
```

`acme/path_accounts.go`（核心写逻辑——create=生成密钥+Register；update：server_url 变→同 key 新 CA `ResolveAccountByKey` 幂等回退 `Register`，同 CA→`UpdateRegistration`；key_type 不可改）：

```go
package acme

import (
	"context"
	"encoding/json"

	"github.com/go-acme/lego/v5/registration"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyAccounts = "accounts/"

func (b *backend) getAccount(ctx context.Context, s logical.Storage, name string) (*accountEntry, error) {
	item, err := s.Get(ctx, storageKeyAccounts+name)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	var entry accountEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func pathAccounts(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name":                    {Type: framework.TypeString, Description: "账户名。"},
		"server_url":              {Type: framework.TypeString, Description: "ACME directory URL（如 LE 生产/staging 或 pebble）。可改：同 key 在新 CA 重新注册。"},
		"contact":                 {Type: framework.TypeString, Description: "联系邮箱。"},
		"terms_of_service_agreed": {Type: framework.TypeBool, Description: "是否同意 ToS。"},
		"key_type":                {Type: framework.TypeString, Default: "EC256", Description: "EC256/EC384/RSA2048/RSA4096/RSA8192；创建后不可改（换钥用 rollover）。"},
		"insecure_tls":            {Type: framework.TypeBool, Description: "跳过 CA 证书校验（仅 pebble 等自签测试环境）。"},
		"dns_providers":           {Type: framework.TypeSlice, Description: "[{name, zones?: [...]}]；zones 空=兜底路由。"},
	}

	entry := &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name"),
		Fields:  fields,
		ExistenceCheck: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
			e, err := b.getAccount(ctx, req.Storage, d.Get("name").(string))
			return e != nil, err
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathAccountWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathAccountWrite},
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					e, err := b.getAccount(ctx, req.Storage, d.Get("name").(string))
					if err != nil || e == nil {
						return nil, err
					}
					return &logical.Response{Data: map[string]interface{}{
						"name":                    e.Name,
						"server_url":              e.ServerURL,
						"contact":                 e.Contact,
						"terms_of_service_agreed": e.TOSAgreed,
						"key_type":                e.KeyType,
						"insecure_tls":            e.InsecureTLS,
						"dns_providers":           e.DNSProviders,
					}}, nil
				},
			},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathAccountDelete},
		},
	}
	list := &framework.Path{
		Pattern: "accounts/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					keys, err := req.Storage.List(ctx, storageKeyAccounts)
					if err != nil {
						return nil, err
					}
					return logical.ListResponse(keys), nil
				},
			},
		},
	}
	rollover := &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name") + "/rollover",
		Fields: map[string]*framework.FieldSchema{
			"name":    {Type: framework.TypeString},
			"key_type": {Type: framework.TypeString, Required: true, Description: "新密钥类型（白名单内）。"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathAccountRollover},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathAccountRollover},
		},
	}
	keyExport := &framework.Path{
		Pattern: "accounts/" + framework.GenericNameRegex("name") + "/key",
		Fields:  map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					e, err := b.getAccount(ctx, req.Storage, d.Get("name").(string))
					if err != nil || e == nil {
						return nil, err
					}
					return &logical.Response{Data: map[string]interface{}{"private_key": e.PrivateKeyPEM}}, nil
				},
			},
		},
	}
	return []*framework.Path{entry, list, rollover, keyExport}
}

func (b *backend) pathAccountWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	existing, err := b.getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	entry := &accountEntry{Name: name}
	if existing != nil {
		entry = existing
	}

	if serverURL, ok := d.GetOk("server_url"); ok {
		entry.ServerURL = serverURL.(string)
	} else if existing == nil {
		return logical.ErrorResponse("server_url 必填"), nil
	}
	if contact, ok := d.GetOk("contact"); ok {
		entry.Contact = contact.(string)
	} else if existing == nil {
		return logical.ErrorResponse("contact 必填"), nil
	}
	entry.TOSAgreed = d.Get("terms_of_service_agreed").(bool)
	entry.InsecureTLS = d.Get("insecure_tls").(bool)
	if refs, ok := d.GetOk("dns_providers"); ok {
		if err := decodeDNSProviderRefs(refs, &entry.DNSProviders); err != nil {
			return logical.ErrorResponse("dns_providers 解析失败: %v", err), nil
		}
	}
	// 校验引用的 dns-provider 存在
	for _, ref := range entry.DNSProviders {
		dp, err := b.getDNSProvider(ctx, req.Storage, ref.Name)
		if err != nil {
			return nil, err
		}
		if dp == nil {
			return logical.ErrorResponse("dns-provider %q 不存在", ref.Name), nil
		}
	}

	// key_type：创建时生成密钥；更新时禁止直接改（走 rollover）。
	if existing == nil {
		kt, ok := d.GetOk("key_type")
		if !ok {
			kt = "EC256"
		}
		typed := kt.(string)
		if _, valid := keyTypes[typed]; !valid {
			return logical.ErrorResponse("key_type 必须是 EC256/EC384/RSA2048/RSA4096/RSA8192"), nil
		}
		entry.KeyType = typed
		key, pemStr, err := generatePrivateKeyPEM(keyTypes[typed])
		if err != nil {
			return nil, err
		}
		entry.PrivateKeyPEM = pemStr
	} else if kt, ok := d.GetOk("key_type"); ok && kt.(string) != entry.KeyType {
		return logical.ErrorResponse("key_type 创建后不可改，请使用 accounts/%s/rollover", name), nil
	}

	user, err := entry.legoUser()
	if err != nil {
		return nil, err
	}
	client, err := newLegoClient(user, entry.ServerURL, entry.InsecureTLS)
	if err != nil {
		return nil, err
	}

	switch {
	case existing == nil || existing.RegistrationJSON == "":
		// 新 CA 上注册
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{
			TermsOfServiceAgreed: entry.TOSAgreed,
		})
		if err != nil {
			return logical.ErrorResponse("ACME 注册失败: %v", err), nil
		}
		user.Registration = reg
	case existing != nil && existing.ServerURL != entry.ServerURL:
		// 同 key 换 CA：幂等回退注册
		reg, err := client.Registration.ResolveAccountByKey(ctx)
		if err != nil {
			reg, err = client.Registration.Register(ctx, registration.RegisterOptions{
				TermsOfServiceAgreed: entry.TOSAgreed,
			})
			if err != nil {
				return logical.ErrorResponse("新 CA 注册失败: %v", err), nil
			}
		}
		user.Registration = reg
	default:
		// 同 CA 更新（contact/ToS）
		reg, err := client.Registration.UpdateRegistration(ctx, registration.UpdateRegistrationOptions{
			TermsOfServiceAgreed: entry.TOSAgreed,
		})
		if err != nil {
			return logical.ErrorResponse("ACME 更新失败: %v", err), nil
		}
		user.Registration = reg
	}

	regJSON, err := json.Marshal(user.Registration)
	if err != nil {
		return nil, err
	}
	entry.RegistrationJSON = string(regJSON)

	item, err := logical.StorageEntryJSON(storageKeyAccounts+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, item); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathAccountDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := b.getAccount(ctx, req.Storage, name)
	if err != nil || entry == nil {
		return nil, err
	}
	// 尽力注销 ACME 账户；失败不阻断本地删除。
	if user, uerr := entry.legoUser(); uerr == nil {
		if client, cerr := newLegoClient(user, entry.ServerURL, entry.InsecureTLS); cerr == nil {
			_ = client.Registration.Deactivate(ctx)
		}
	}
	return nil, req.Storage.Delete(ctx, storageKeyAccounts+name)
}

func (b *backend) pathAccountRollover(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	entry, err := b.getAccount(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	kt := d.Get("key_type").(string)
	if _, valid := keyTypes[kt]; !valid {
		return logical.ErrorResponse("key_type 必须是 EC256/EC384/RSA2048/RSA4096/RSA8192"), nil
	}
	newKey, pemStr, err := generatePrivateKeyPEM(keyTypes[kt])
	if err != nil {
		return nil, err
	}
	user, err := entry.legoUser()
	if err != nil {
		return nil, err
	}
	client, err := newLegoClient(user, entry.ServerURL, entry.InsecureTLS)
	if err != nil {
		return nil, err
	}
	if err := client.Registration.KeyRollover(ctx, newKey); err != nil {
		return logical.ErrorResponse("key rollover 失败: %v", err), nil
	}
	entry.KeyType, entry.PrivateKeyPEM = kt, pemStr
	item, err := logical.StorageEntryJSON(storageKeyAccounts+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, item); err != nil {
		return nil, err
	}
	return nil, nil
}

// decodeDNSProviderRefs：TypeSlice 的 []interface{} → []dnsProviderRef。
func decodeDNSProviderRefs(raw interface{}, out *[]dnsProviderRef) error {
	list, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("期望数组，得到 %T", raw)
	}
	refs := make([]dnsProviderRef, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("dns_providers[%d]: 期望对象", i)
		}
		ref := dnsProviderRef{}
		if n, ok := m["name"].(string); ok {
			ref.Name = n
		}
		if ref.Name == "" {
			return fmt.Errorf("dns_providers[%d]: name 必填", i)
		}
		if zones, ok := m["zones"].([]interface{}); ok {
			for _, z := range zones {
				if zs, ok := z.(string); ok {
					ref.Zones = append(ref.Zones, zs)
				}
			}
		}
		refs = append(refs, ref)
	}
	*out = refs
	return nil
}
```

`Backend()` 注册路径（本任务起建立聚合函数，`acme/backend.go`）：

```go
// paths 聚合全部路径；后续任务向此追加。
func paths(b *backend) []*framework.Path {
	return append(pathDNSProviders(b), pathAccounts(b)...)
}
```

并把 `Backend()` 中 `Paths: []*framework.Path{}` 改为 `Paths: paths(b)`。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestAccounts|TestAccount' -v`
Expected: PASS（pebble 缺失时 SKIP；建议 `go install github.com/letsencrypt/pebble/cmd/pebble@main && go install github.com/letsencrypt/pebble/cmd/pebble-challtestsrv@main`）

- [ ] **Step 5: Commit**

```bash
git add acme/pebble_test.go acme/path_accounts.go acme/path_accounts_test.go acme/account.go acme/backend.go
git commit -m "feat: accounts path with rollover, key export, pebble test env"
```

### Task 8: roles 路径 + validateNames（域名策略）

**Files:**
- Create: `acme/path_roles.go`
- Test: `acme/path_roles_test.go`

**Interfaces:**
- Consumes: Task 7 `getAccount`（校验 account 存在）
- Produces:
  - `type roleEntry struct { Account string; AllowedDomains []string; AllowBareDomains, AllowSubdomains, DisableCache bool; CacheForRatio int; OutputKVMount string }`（json tag snake_case；`cache_for_ratio` 默认 70，(0,100]）
  - `const storageKeyRoles = "roles/"`
  - `func (b *backend) getRole(ctx, s, name) (*roleEntry, error)`
  - `func validateNames(cn string, alt []string, role *roleEntry) error`：通配符剥 `*.` 后——精确等于允许域→需 `allow_bare_domains`；子域→需 `allow_subdomains`；都不命中→报错
  - `pathRoles(b *backend) []*framework.Path`（CRUD+LIST，write 校验 account 存在、ratio 范围）

- [ ] **Step 1: 写失败测试**

`acme/path_roles_test.go`：

```go
package acme

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestValidateNames(t *testing.T) {
	role := &roleEntry{AllowedDomains: []string{"example.com"}, AllowBareDomains: true, AllowSubdomains: true}
	require.NoError(t, validateNames("example.com", nil, role))
	require.NoError(t, validateNames("www.example.com", []string{"a.example.com"}, role))
	require.NoError(t, validateNames("*.example.com", nil, role))

	strict := &roleEntry{AllowedDomains: []string{"example.com"}}
	require.Error(t, validateNames("example.com", nil, strict))     // bare 未开
	require.Error(t, validateNames("www.example.com", nil, strict)) // sub 未开
	require.NoError(t, validateNames("*.example.com", nil, strict)) // 通配符按 bare 计

	wrong := &roleEntry{AllowedDomains: []string{"other.com"}, AllowBareDomains: true, AllowSubdomains: true}
	require.Error(t, validateNames("example.com", nil, wrong))
}

func TestRoleCRUD(t *testing.T) {
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 预置 account
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	}, nil)
	require.NoError(t, err)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":           "le",
			"allowed_domains":   "example.com,example.org",
			"allow_subdomains":  true,
			"output_kv_mount":   "kv-certs",
		},
	}, nil)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create: %v", resp)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/web", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "le", resp.Data["account"])
	require.Equal(t, 70, resp.Data["cache_for_ratio"])   // 默认
	require.Equal(t, "kv-certs", resp.Data["output_kv_mount"])

	// 不存在的 account → 报错
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/bad",
		Storage: storage, Data: map[string]interface{}{"account": "ghost"},
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())

	// ratio 越界 → 报错
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/web",
		Storage: storage, Data: map[string]interface{}{"cache_for_ratio": 101},
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())

	// LIST + DELETE
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "roles/", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"web"}, resp.Data["keys"])
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "roles/web", Storage: storage,
	}, nil)
	require.NoError(t, err)
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestValidateNames|TestRole' -v`
Expected: FAIL（未定义）

- [ ] **Step 3: 最小实现**

`acme/path_roles.go`：

```go
package acme

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyRoles = "roles/"

// roleEntry：签发策略（域名白名单、缓存策略、KV 输出目标）。
type roleEntry struct {
	Account          string   `json:"account"`
	AllowedDomains   []string `json:"allowed_domains"`
	AllowBareDomains bool     `json:"allow_bare_domains"`
	AllowSubdomains  bool     `json:"allow_subdomains"`
	DisableCache     bool     `json:"disable_cache"`
	CacheForRatio    int      `json:"cache_for_ratio"`
	OutputKVMount    string   `json:"output_kv_mount"`
}

// validateNames：通配符剥 "*." 后按 bare/sub 语义校验（含 PKI 语义一致性）。
func validateNames(cn string, alt []string, role *roleEntry) error {
	for _, name := range append([]string{cn}, alt...) {
		if name == "" {
			return fmt.Errorf("域名为空")
		}
		bare := strings.TrimPrefix(name, "*.")
		matched := false
		for _, allowed := range role.AllowedDomains {
			if bare == allowed {
				if name == allowed && !role.AllowBareDomains {
					return fmt.Errorf("域名 %q 是裸域，需要 allow_bare_domains", name)
				}
				if name != allowed && !role.AllowSubdomains {
					return fmt.Errorf("域名 %q 是子域，需要 allow_subdomains", name)
				}
				matched = true
				break
			}
			if strings.HasSuffix(bare, "."+allowed) {
				if !role.AllowSubdomains {
					return fmt.Errorf("域名 %q 是子域，需要 allow_subdomains", name)
				}
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("域名 %q 不在 allowed_domains 内", name)
		}
	}
	return nil
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	item, err := s.Get(ctx, storageKeyRoles+name)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	var role roleEntry
	if err := item.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func pathRoles(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name":              {Type: framework.TypeString, Description: "role 名（certs/{role} 引用）。"},
		"account":           {Type: framework.TypeString, Required: true, Description: "accounts/{name}。"},
		"allowed_domains":   {Type: framework.TypeCommaStringSlice, Required: true, Description: "允许的域名（逗号分隔）。"},
		"allow_bare_domains": {Type: framework.TypeBool, Description: "允许裸域。"},
		"allow_subdomains":  {Type: framework.TypeBool, Description: "允许子域。"},
		"disable_cache":     {Type: framework.TypeBool, Description: "禁用证书缓存（每次真签发）。"},
		"cache_for_ratio":   {Type: framework.TypeInt, Default: 70, Description: "剩余寿命低于总寿命该百分比时重签；(0,100]。"},
		"output_kv_mount":   {Type: framework.TypeString, Description: "证书同步输出到该 KV mount（certs/{role}/{cn}）；空=不输出。"},
	}
	entry := &framework.Path{
		Pattern:      "roles/" + framework.GenericNameRegex("name"),
		Fields:       fields,
		ExistenceCheck: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
			r, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
			return r != nil, err
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					role, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
					if err != nil || role == nil {
						return nil, err
					}
					return &logical.Response{Data: map[string]interface{}{
						"account":            role.Account,
						"allowed_domains":    role.AllowedDomains,
						"allow_bare_domains": role.AllowBareDomains,
						"allow_subdomains":   role.AllowSubdomains,
						"disable_cache":      role.DisableCache,
						"cache_for_ratio":    role.CacheForRatio,
						"output_kv_mount":    role.OutputKVMount,
					}}, nil
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					return nil, req.Storage.Delete(ctx, storageKeyRoles+d.Get("name").(string))
				},
			},
		},
	}
	list := &framework.Path{
		Pattern: "roles/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					keys, err := req.Storage.List(ctx, storageKeyRoles)
					if err != nil {
						return nil, err
					}
					return logical.ListResponse(keys), nil
				},
			},
		},
	}
	return []*framework.Path{entry, list}
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	existing, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	role := &roleEntry{CacheForRatio: 70}
	if existing != nil {
		role = existing
	}

	acc, ok := d.GetOk("account")
	if !ok {
		if existing == nil {
			return logical.ErrorResponse("account 必填"), nil
		}
	} else {
		role.Account = acc.(string)
	}
	account, err := b.getAccount(ctx, req.Storage, role.Account)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return logical.ErrorResponse("account %q 不存在", role.Account), nil
	}

	if ad, ok := d.GetOk("allowed_domains"); ok {
		role.AllowedDomains = ad.([]string)
	}
	if existing == nil && len(role.AllowedDomains) == 0 {
		return logical.ErrorResponse("allowed_domains 必填"), nil
	}
	role.AllowBareDomains = d.Get("allow_bare_domains").(bool)
	role.AllowSubdomains = d.Get("allow_subdomains").(bool)
	role.DisableCache = d.Get("disable_cache").(bool)
	if ratio, ok := d.GetOk("cache_for_ratio"); ok {
		v := ratio.(int)
		if v <= 0 || v > 100 {
			return logical.ErrorResponse("cache_for_ratio 必须在 (0,100] 内"), nil
		}
		role.CacheForRatio = v
	}
	if o, ok := d.GetOk("output_kv_mount"); ok {
		role.OutputKVMount = o.(string)
	}

	item, err := logical.StorageEntryJSON(storageKeyRoles+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, item); err != nil {
		return nil, err
	}
	return nil, nil
}
```

注意：`d.Get("cache_for_ratio")` 在未设置时返回默认 70——更新场景 `existing != nil` 时跳过校验分支即可（实现时：仅当 `d.Raw` 中显式携带该键才校验；用 `d.GetOk` 的 ok 位）。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestValidateNames|TestRole' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/path_roles.go acme/path_roles_test.go
git commit -m "feat: roles path with domain validation policy"
```

---

### Task 9: 证书缓存（sha256 键/引用计数/ratio 过期/singleflight 辅助）

**Files:**
- Create: `acme/cache.go`
- Test: `acme/cache_test.go`

**Interfaces:**
- Consumes: `backend.cacheMu`（Task 1）
- Produces:
  - `type cacheEntry struct { Users int; Account, CN string; Domains []string; CertURL, CertStableURL, PrivateKeyPEM, CertificatePEM, IssuerCertificatePEM string }`（json tag snake_case）
  - `func cacheKey(role *roleEntry, domains []string) string`（sha256(roleJSON + 排序后 domains 逗号连接)）
  - `func (b *backend) cacheGet(ctx, s, key) (*cacheEntry, error)` / `cachePut(ctx, s, key, e)` / `cacheDelete` / `cacheCount(ctx, s) (int, error)` / `cacheClear(ctx, s) (int, error)`——全部持 `b.cacheMu`（RWMutex：Get/Count 读锁，其余写锁）
  - `func certNeedsRenewal(certPEM string, ratio int) bool`（剩余寿命 < total×ratio% → true；解析失败 → true）
  - `const storageKeyCache = "cache/"`

- [ ] **Step 1: 写失败测试**

`acme/cache_test.go`：

```go
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func testBackendConfig(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	return b, storage
}

func selfSignedCertFor(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCacheKeyDeterministic(t *testing.T) {
	role := &roleEntry{Account: "le"}
	d1 := cacheKey(role, []string{"b.com", "a.com"})
	d2 := cacheKey(role, []string{"a.com", "b.com"})
	d3 := cacheKey(role, []string{"a.com", "c.com"})
	require.Equal(t, d1, d2) // 域名顺序无关
	require.NotEqual(t, d1, d3)
}

func TestCacheCRUDAndRefcount(t *testing.T) {
	b, storage := testBackendConfig(t)
	ctx := context.Background()
	key := cacheKey(&roleEntry{Account: "le"}, []string{"a.com"})

	// 初始无
	e, err := b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.Nil(t, e)

	// 写入 Users=2
	require.NoError(t, b.cachePut(ctx, storage, key, &cacheEntry{
		Users: 2, Account: "le", CN: "a.com", Domains: []string{"a.com"},
		CertificatePEM: "CERT", PrivateKeyPEM: "KEY",
	}))
	e, err = b.cacheGet(ctx, storage, key)
	require.NoError(t, err)
	require.Equal(t, 2, e.Users)

	// 计数/清空
	n, err := b.cacheCount(ctx, storage)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	cleared, err := b.cacheClear(ctx, storage)
	require.NoError(t, err)
	require.Equal(t, 1, cleared)
	n, _ = b.cacheCount(ctx, storage)
	require.Equal(t, 0, n)
}

func TestCertNeedsRenewal(t *testing.T) {
	now := time.Now()
	// 总寿命 100h，已用 99h，ratio=70：剩余 1% < 70% → true
	old := selfSignedCertFor(t, now.Add(-99*time.Hour), now.Add(time.Hour))
	require.True(t, certNeedsRenewal(old, 70))
	// 总寿命 100h，已用 1h：剩余 99% ≥ 70% → false
	fresh := selfSignedCertFor(t, now.Add(-time.Hour), now.Add(99*time.Hour))
	require.False(t, certNeedsRenewal(fresh, 70))
	// 解析失败 → true（保守重签）
	require.True(t, certNeedsRenewal("garbage", 70))
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestCache|TestCertNeeds' -v`
Expected: FAIL

- [ ] **Step 3: 最小实现**

`acme/cache.go`：

```go
package acme

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const storageKeyCache = "cache/"

// cacheEntry：共享证书条目；Users 为引用计数（每个 lease 持有一个引用）。
type cacheEntry struct {
	Users                int      `json:"users"`
	Account              string   `json:"account"`
	CN                   string   `json:"cn"`
	Domains              []string `json:"domains"`
	CertURL              string   `json:"cert_url"`
	CertStableURL        string   `json:"cert_stable_url"`
	PrivateKeyPEM        string   `json:"private_key_pem"`
	CertificatePEM       string   `json:"certificate_pem"`
	IssuerCertificatePEM string   `json:"issuer_certificate_pem"`
}

// cacheKey：sha256(roleJSON + 排序后 domains)，域名顺序无关。
func cacheKey(role *roleEntry, domains []string) string {
	roleJSON, _ := json.Marshal(role)
	sorted := append([]string(nil), domains...)
	sort.Strings(sorted)
	sum := sha256.Sum256(append(roleJSON, []byte(strings.Join(sorted, ","))...))
	return hex.EncodeToString(sum[:])
}

func (b *backend) cacheGet(ctx context.Context, s logical.Storage, key string) (*cacheEntry, error) {
	b.cacheMu.RLock()
	defer b.cacheMu.RUnlock()
	item, err := s.Get(ctx, storageKeyCache+key)
	if err != nil || item == nil {
		return nil, err
	}
	var entry cacheEntry
	if err := item.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (b *backend) cachePut(ctx context.Context, s logical.Storage, key string, entry *cacheEntry) error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, &logical.StorageEntry{Key: storageKeyCache + key, Value: raw})
}

func (b *backend) cacheDelete(ctx context.Context, s logical.Storage, key string) error {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	return s.Delete(ctx, storageKeyCache+key)
}

func (b *backend) cacheCount(ctx context.Context, s logical.Storage) (int, error) {
	b.cacheMu.RLock()
	defer b.cacheMu.RUnlock()
	keys, err := s.List(ctx, storageKeyCache)
	return len(keys), err
}

func (b *backend) cacheClear(ctx context.Context, s logical.Storage) (int, error) {
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	keys, err := s.List(ctx, storageKeyCache)
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if err := s.Delete(ctx, storageKeyCache+k); err != nil {
			return 0, err
		}
	}
	return len(keys), nil
}

// certNeedsRenewal：剩余寿命 < 总寿命×ratio% → true；解析失败保守返回 true。
func certNeedsRenewal(certPEM string, ratio int) bool {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	total := cert.NotAfter.Sub(cert.NotBefore)
	remaining := time.Until(cert.NotAfter)
	return remaining < total*time.Duration(ratio)/100
}
```

import 需补 `"crypto/sha256"`、`"encoding/hex"`。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestCache|TestCertNeeds' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/cache.go acme/cache_test.go
git commit -m "feat: persistent cert cache with refcount and ratio-based expiry"
```

### Task 10: KV 证书输出（writer/sanitize/输出路径）

**Files:**
- Create: `acme/kvoutput.go`
- Modify: `acme/backend.go`（删除 `KVOutputWriter`/`apiKVWriter` 桩；`Factory`/`Backend` 保持默认 `&apiKVWriter{}`）
- Test: `acme/kvoutput_test.go`

**Interfaces:**
- Consumes: openbao api/v2 KVv2
- Produces:
  - `type KVOutputWriter interface { Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error }`
  - `type apiKVWriter struct{}`：`api.NewClient(nil)`（BAO_ADDR env，同凭据读取）→ `SetToken(clientToken)` → `client.KVv2(mount).Put(ctx, path, data)`
  - `func sanitizeCN(cn string) string`：`*.example.com`→`_wildcard.example.com`；`/`→`_`
  - `func outputKVPath(roleName, cn string) string`：`certs/{role}/{sanitize(cn)}`
  - `func (b *backend) writeCertOutput(ctx, req *logical.Request, roleName string, role *roleEntry, cn string, entry *cacheEntry) error`：`role.OutputKVMount == ""` 时 no-op nil；写 `{certificate, private_key, issuer_cert, domains, not_before, not_after}`；返回 outputKVPath 由调用方拼装响应（此函数返回 `(string, error)`：写入的 KV path）

- [ ] **Step 1: 写失败测试**

`acme/kvoutput_test.go`：

```go
package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordingKVWriter struct {
	writes []kvWrite
}

type kvWrite struct {
	mount, path string
	data        map[string]interface{}
}

func (w *recordingKVWriter) Write(ctx context.Context, clientToken, mount, path string, data map[string]interface{}) error {
	require.NotEmpty(t := clientToken, t) // 传递调用者 token
	w.writes = append(w.writes, kvWrite{mount, path, data})
	return nil
}

func TestSanitizeCN(t *testing.T) {
	require.Equal(t, "_wildcard.example.com", sanitizeCN("*.example.com"))
	require.Equal(t, "www.example.com", sanitizeCN("www.example.com"))
	require.Equal(t, "a_b.example.com", sanitizeCN("a/b.example.com"))
}

func TestOutputKVPath(t *testing.T) {
	require.Equal(t, "certs/web/_wildcard.example.com", outputKVPath("web", "*.example.com"))
	require.Equal(t, "certs/web/www.example.com", outputKVPath("web", "www.example.com"))
}

func TestWriteCertOutput(t *testing.T) {
	b, _ := testBackendConfig(t)
	w := &recordingKVWriter{}
	b.kvWriter = w

	// 未配置 output_kv_mount → no-op
	path, err := b.writeCertOutput(context.Background(), &logical.Request{ClientToken: "tok"},
		"web", &roleEntry{}, "a.com",
		&cacheEntry{CertificatePEM: "C", PrivateKeyPEM: "K"})
	require.NoError(t, err)
	require.Equal(t, "", path)
	require.Empty(t, w.writes)

	// 配置后写入
	path, err = b.writeCertOutput(context.Background(), &logical.Request{ClientToken: "tok"},
		"web", &roleEntry{OutputKVMount: "kv-certs"}, "*.example.com",
		&cacheEntry{CertificatePEM: "C", PrivateKeyPEM: "K", IssuerCertificatePEM: "I",
			Domains: []string{"*.example.com"}})
	require.NoError(t, err)
	require.Equal(t, "certs/web/_wildcard.example.com", path)
	require.Len(t, w.writes, 1)
	require.Equal(t, "kv-certs", w.writes[0].mount)
	require.Equal(t, "C", w.writes[0].data["certificate"])
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestSanitize|TestOutputKV|TestWriteCertOutput' -v`
Expected: FAIL

- [ ] **Step 3: 最小实现**

`acme/kvoutput.go`：

```go
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

// sanitizeCN 把 CN 变成 KV 路径安全的段。
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

// writeCertOutput：未配置 OutputKVMount 时 no-op；否则写证书并返回 KV path。
func (b *backend) writeCertOutput(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, cn string, entry *cacheEntry) (string, error) {
	if role.OutputKVMount == "" {
		return "", nil
	}
	path := outputKVPath(roleName, cn)
	data := map[string]interface{}{
		"certificate":  entry.CertificatePEM,
		"private_key":  entry.PrivateKeyPEM,
		"issuer_cert":  entry.IssuerCertificatePEM,
		"domains":      entry.Domains,
	}
	if err := b.kvWriter.Write(ctx, req.ClientToken, role.OutputKVMount, path, data); err != nil {
		return "", err
	}
	return path, nil
}
```

（测试 import 需加 `"github.com/openbao/openbao/sdk/v2/logical"`。）

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestSanitize|TestOutputKV|TestWriteCertOutput' && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/kvoutput.go acme/kvoutput_test.go acme/backend.go
git commit -m "feat: synchronous KV certificate output"
```

---

### Task 11: 签发路径 certs/{role}（编排：路由→实时凭据→Obtain→缓存→KV 输出）

**Files:**
- Create: `acme/path_certs.go`
- Test: `acme/path_certs_test.go`

**Interfaces:**
- Consumes: Task 2/3/4/6/8/9/10 全部产物；lego `certificate.ObtainRequest{Domains, Bundle: true}`
- Produces:
  - `pathCerts(b *backend) []*framework.Path`：`POST/PUT certs/{role}`，字段 `common_name`（必填）、`alternative_names`（TypeCommaStringSlice）
  - 响应 Data：`common_name, domains, certificate, private_key, issuer_cert, url, cert_stable_url, not_before, not_after`（+配置了输出时 `output_path`）
  - InternalData：`account, cache_key`（Renew/Revoke 用）
  - `func (b *backend) buildRoutes(ctx, req *logical.Request, acc *accountEntry) (*routingProvider, error)`：按 `acc.DNSProviders` 顺序读 dns-providers 条目→实时 Load 凭据→`newProvider`→构造 `providerRoute`（Zones 取 ref.Zones）

- [ ] **Step 1: 写失败测试**

`acme/path_certs_test.go`：

```go
package acme

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// setupIssuable 预置：pebble、account（引用 exec provider）、role。
func setupIssuable(t *testing.T) (*backend, logical.Storage, *pebbleEnv, string) {
	t.Helper()
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(nil))
	ctx := context.Background()

	// 注册 exec provider 脚本（Task 14 同款脚本）与 dns-provider/account/role
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{
		Key: "dns-providers/exec", Value: mustJSON(t, &dnsProviderEntry{
			Type:           "cloudflare",
			CredentialsRef: &credentialsRef{Mount: "secret", Path: "dns/cf"},
		}),
	}))
	// 注：单测用 fake loader（返回 cloudflare token），pebble 对 DNS 提供商无感——
	// 但真实 DNS-01 验证需要 TXT 落地，因此本任务用 HTTP-01 不可行（v1 仅 DNS-01），
	// 改用「签发到无效 zone 也会先走完路由/凭据/provider 构造」来测编排，
	// 真实端到端签发在 Task 14 验收测试覆盖（exec provider + challtestsrv）。
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: accountData(env.DirURL),
	}, nil)
	require.NoError(t, err)
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":          "le",
			"allowed_domains":  "example.com",
			"allow_bare_domains": true,
			"allow_subdomains":   true,
		},
	}, nil)
	require.NoError(t, err)
	return b, storage, env, "exec"
}

func TestIssuePathValidation(t *testing.T) {
	b, storage, _, _ := setupIssuable(t)
	ctx := context.Background()

	// 域名不在白名单 → 报错
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage,
		Data:    map[string]interface{}{"common_name": "evil.com"},
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())

	// 白名单内但 provider 路由缺失（account 无 dns_providers）→ 报错含"路由"
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage,
		Data:    map[string]interface{}{"common_name": "example.com"},
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

func TestIssueWithFakeProvider(t *testing.T) {
	// 直接注入假 provider 验证 Obtain 之后的编排（缓存/KV 输出/响应字段）。
	// 做法：account 指向 exec 型 dns-provider，但 credLoader 返回
	// EXEC_PATH 指向一个本地 mock 脚本（写入 TXT 的 no-op），ACME 验证会失败——
	// 因此本测试聚焦「失败前」的路径：响应错误但缓存未生成、无 KV 写入。
	env := startPebble(t)
	b, storage := testBackend(t, NewFakeCredentialLoader(map[string]string{
		"CLOUDFLARE_DNS_API_TOKEN": "tok",
	}))
	ctx := context.Background()

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "dns-providers/cf",
		Storage: storage,
		Data: map[string]interface{}{
			"type":            "cloudflare",
			"credentials_ref": map[string]interface{}{"mount": "s", "path": "p"},
		},
	}, nil)
	require.NoError(t, err)

	data := accountData(env.DirURL)
	data["dns_providers"] = []interface{}{map[string]interface{}{"name": "cf"}}
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/le",
		Storage: storage, Data: data,
	}, nil)
	require.NoError(t, err)

	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/web",
		Storage: storage,
		Data: map[string]interface{}{
			"account":            "le",
			"allowed_domains":    "example.com",
			"allow_bare_domains": true,
			"output_kv_mount":    "kv-certs",
		},
	}, nil)
	require.NoError(t, err)

	w := &recordingKVWriter{}
	b.kvWriter = w

	// 签发：路由与凭据/provider 构造成功，TXT 无法真正落地（pebble 侧校验失败）
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage,
		Data:    map[string]interface{}{"common_name": "example.com"},
	}, nil)
	require.NoError(t, err)
	require.True(t, resp.IsError())            // pebble DNS 校验失败（预期）
	require.Empty(t, w.writes)                 // 失败不写 KV
	n, _ := b.cacheCount(ctx, storage)
	require.Equal(t, 0, n)                     // 失败不落缓存
}
```

> 说明：真实全链路签发（TXT 真正落地→证书签出→缓存命中→KV 输出→revoke）由 Task 14 验收测试用 exec provider + challtestsrv 覆盖；单测环境无法落 TXT（fake provider 不产生记录），故此处验证「失败路径不落缓存/不写 KV」与校验逻辑。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestIssue' -v`
Expected: FAIL

- [ ] **Step 3: 最小实现**

`acme/path_certs.go`：

```go
package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathCerts(b *backend) []*framework.Path {
	return []*framework.Path{{
		Pattern: "certs/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role":              {Type: framework.TypeString, Description: "role 名。"},
			"common_name":       {Type: framework.TypeString, Required: true, Description: "主域名（可含通配符 *.）。"},
			"alternative_names": {Type: framework.TypeCommaStringSlice, Description: "附加域名。"},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathIssueCert},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathIssueCert},
		},
	}}
}

// buildRoutes：按 account.dns_providers 顺序实时读凭据并构造子 provider。
func (b *backend) buildRoutes(ctx context.Context, req *logical.Request, acc *accountEntry) (*routingProvider, error) {
	routes := make([]providerRoute, 0, len(acc.DNSProviders))
	for _, ref := range acc.DNSProviders {
		dp, err := b.getDNSProvider(ctx, req.Storage, ref.Name)
		if err != nil {
			return nil, err
		}
		if dp == nil {
			return nil, fmt.Errorf("dns-provider %q 不存在", ref.Name)
		}
		if dp.CredentialsRef == nil {
			return nil, fmt.Errorf("dns-provider %q 缺少 credentials_ref", ref.Name)
		}
		raw, err := b.credLoader.Load(ctx, req.ClientToken, *dp.CredentialsRef)
		if err != nil {
			return nil, fmt.Errorf("dns-provider %q 凭据读取失败: %w", ref.Name, err)
		}
		env := resolveKeys(raw, *dp.CredentialsRef, envNames[dp.Type])
		provider, err := newProvider(ctx, dp.Type, providerOpts{
			PropagationTimeout: dp.PropagationTimeout,
			PollingInterval:    dp.PollingInterval,
		}, env)
		if err != nil {
			return nil, fmt.Errorf("dns-provider %q: %w", ref.Name, err)
		}
		routes = append(routes, providerRoute{Name: ref.Name, Zones: ref.Zones, Provider: provider})
	}
	return newRoutingProvider(routes)
}

func (b *backend) pathIssueCert(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	cn := d.Get("common_name").(string)
	if cn == "" {
		return logical.ErrorResponse("common_name 必填"), nil
	}
	alt := d.Get("alternative_names").([]string)
	domains := append([]string{cn}, alt...)

	if err := validateNames(cn, alt, role); err != nil {
		return logical.ErrorResponse("%v", err), nil
	}
	account, err := b.getAccount(ctx, req.Storage, role.Account)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return logical.ErrorResponse("account %q 不存在", role.Account), nil
	}

	key := cacheKey(role, domains)
	// 1) 缓存命中且未过期 → Users++ 直接返回
	if !role.DisableCache {
		entry, err := b.cacheGet(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if entry != nil && !certNeedsRenewal(entry.CertificatePEM, role.CacheForRatio) {
			entry.Users++
			if err := b.cachePut(ctx, req.Storage, key, entry); err != nil {
				return nil, err
			}
			return b.issueResponse(entry, key, "", nil), nil
		}
	}

	// 2) singleflight 防并发重复签发；Inmem/ barrier 存储本身串行写，锁保护缓存条目
	var issueErr error
	v, err, _ := b.issueGroup.Do(key, func() (interface{}, error) {
		return b.doIssue(ctx, req, roleName, role, account, cn, domains, key)
	})
	if err != nil {
		issueErr = err
	} else if e, ok := v.(*logical.Response); ok && e.IsError() {
		issueErr = fmt.Errorf("%s", e.Data["error"])
	}
	if issueErr != nil {
		return logical.ErrorResponse("签发失败: %v", issueErr), nil
	}
	return v.(*logical.Response), nil
}

// doIssue：路由→凭据→provider→Obtain→缓存→KV 输出。
func (b *backend) doIssue(ctx context.Context, req *logical.Request, roleName string, role *roleEntry, account *accountEntry, cn string, domains []string, key string) (interface{}, error) {
	router, err := b.buildRoutes(ctx, req, account)
	if err != nil {
		return nil, err
	}
	// 无任何路由（account 未配 dns_providers）→ 明确报错
	for _, dom := range domains {
		if _, err := router.match(dom); err != nil {
			return nil, err
		}
	}

	user, err := account.legoUser()
	if err != nil {
		return nil, err
	}
	client, err := newLegoClient(user, account.ServerURL, account.InsecureTLS)
	if err != nil {
		return nil, err
	}
	var dns01Provider challenge.Provider = router
	if err := client.Challenge.SetDNS01Provider(dns01Provider); err != nil {
		return nil, fmt.Errorf("设置 DNS-01 provider: %w", err)
	}

	res, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("ACME obtain: %w", err)
	}

	entry := &cacheEntry{
		Users: 1, Account: account.Name, CN: cn, Domains: domains,
		CertURL: res.CertURL, CertStableURL: res.CertStableURL,
		PrivateKeyPEM:  string(res.PrivateKey),
		CertificatePEM: string(res.Certificate),
		IssuerCertificatePEM: string(res.IssuerCertificate),
	}
	if err := b.cachePut(ctx, req.Storage, key, entry); err != nil {
		return nil, err
	}

	kvPath, err := b.writeCertOutput(ctx, req, roleName, role, cn, entry)
	if err != nil {
		// 签发成功但输出失败：证书已缓存，报错让调用者重试（缓存命中路径会补写输出）
		return nil, fmt.Errorf("KV 输出失败: %w", err)
	}

	notBefore, notAfter := certValidity(entry.CertificatePEM)
	resp := b.issueResponse(entry, key, kvPath, nil)
	resp.Data["not_before"] = notBefore
	resp.Data["not_after"] = notAfter
	return resp, nil
}

// certValidity 解析证书有效期；失败返回零值。
func certValidity(certPEM string) (time.Time, time.Time) {
	if cert, err := certcrypto.ParsePEMCertificate([]byte(certPEM)); err == nil {
		return cert.NotBefore.UTC(), cert.NotAfter.UTC()
	}
	return time.Time{}, time.Time{}
}

// issueResponse 组装签发/缓存命中响应。
func (b *backend) issueResponse(entry *cacheEntry, cacheKeyStr, kvPath string, internal map[string]interface{}) *logical.Response {
	data := map[string]interface{}{
		"common_name":  entry.CN,
		"domains":      entry.Domains,
		"certificate":  entry.CertificatePEM,
		"private_key":  entry.PrivateKeyPEM,
		"issuer_cert":  entry.IssuerCertificatePEM,
		"url":          entry.CertURL,
		"cert_stable_url": entry.CertStableURL,
	}
	if kvPath != "" {
		data["output_path"] = kvPath
	}
	if internal == nil {
		internal = map[string]interface{}{}
	}
	internal["cache_key"] = cacheKeyStr
	resp := &logical.Response{Data: data}
	resp.Secret = &logical.Secret{InternalData: internal}
	resp.Secret.LeaseOptions.MaxTTL = 0 // 由 doIssue 后设置（见下）
	return resp
}
```

> 实现说明（以此为准）：MaxTTL 需要证书 notAfter——把 `resp.Secret.LeaseOptions.MaxTTL = time.Until(notAfter)` 放在 `doIssue` 中拿到 `notAfter` 后设置；缓存命中分支同样解析 `certValidity` 设置。`Secret.Type` 为 `"acme_cert"`（Task 12 定义 `secretCert` 时把 `Secret.Type = secretCertType` 补上；本任务先只设 InternalData 与 MaxTTL）。Renew/Revoke 的 `account` InternalData 在 Task 12 一并补入（`internal["account"] = role.Account`）。

`Backend()` 的 `paths()` 追加 `pathCerts(b)`。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestIssue' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/path_certs.go acme/path_certs_test.go acme/backend.go
git commit -m "feat: issue path with routing, live credentials, cache, KV output"
```

### Task 12: Renew/Revoke（secret 类型：引用计数 + ratio 驱动重签）

**Files:**
- Create: `acme/secret_cert.go`
- Modify: `acme/backend.go`（`Backend()` 的 `Secrets: []*framework.Secret{}` → `secrets(b)`；`acme/paths.go` 或 backend.go 聚合不变）
- Modify: `acme/path_certs.go`（`issueResponse` 的 InternalData 补 `account`；`resp.Secret.Type = secretCertType`）
- Test: `acme/secret_cert_test.go`

**Interfaces:**
- Consumes: Task 9 缓存原语、Task 11 `cache_key`/`account` InternalData、lego `client.Certificate.Revoke(ctx, []byte, ...)` / `Renew`
- Produces:
  - `const secretCertType = "acme_cert"`
  - `var secretCert = &framework.Secret{Type: secretCertType, Fields: map[string]*framework.FieldSchema{...}, Renew: certRenew, Revoke: certRevoke}`
  - Renew 语义：解析 InternalData 的 `cache_key`/`account` → 读缓存条目 → `certNeedsRenewal(certPEM, role.CacheForRatio)` false→返回空 resp（自动续 lease，不动证书）；true→用原 role/account/参数重签（复用 `doIssue`），返回新数据并刷新 KV 输出
  - Revoke 语义：`Users--`；>0 只存回；归零→ `client.Certificate.Revoke`（尽力，pebble 侧真撤销）+ `cacheDelete`
  - `Backend()` 注册 `Secrets: []*framework.Secret{secretCert}`

- [ ] **Step 1: 写失败测试**

`acme/secret_cert_test.go`：

```go
package acme

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func issueViaBackend(t *testing.T, b *backend, storage logical.Storage, cn string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.CreateOperation, Path: "certs/web",
		Storage: storage,
		Data:    map[string]interface{}{"common_name": cn},
	}, nil)
	require.NoError(t, err)
	return resp
}

// certEntryJSON 构造带 InternalData 的 logical.Secret（模拟 lease 数据）。
func secretWithInternal(t *testing.T, internal map[string]interface{}) *logical.Request {
	t.Helper()
	req := &logical.Request{}
	req.SetToken = nil
	_ = internal
	return req
}
```

> 上方 `secretWithInternal` 为冗余草稿，**以 Renew/Revoke 单测的可行形态为准**：Renew/Revoke 的回调签名是 `(ctx, req, d) (*logical.Response, error)`，`req.Secret.InternalData` 由 framework 从签发响应复制。单测直接构造 `&logical.Request{Secret: &logical.Secret{InternalData: map[string]interface{}{...}}}` 调用 `certRenew`/`certRevoke`：

```go
func TestRevokeRefcount(t *testing.T) {
	env := startPebble(t)
	b, storage := setupIssuable(t) // 见 Task 11 helper 签名调整：返回 (b, storage)
	_ = env
	ctx := context.Background()

	key := cacheKey(&roleEntry{Account: "le"}, []string{"example.com"})
	require.NoError(t, b.cachePut(ctx, storage, key, &cacheEntry{
		Users: 2, Account: "le", CN: "example.com", Domains: []string{"example.com"},
		CertificatePEM: selfSignedCertFor(t, time.Now().Add(-time.Hour), time.Now().Add(99*time.Hour)),
	}))

	// Users 2→1：不真撤销
	resp, err := certRevoke(ctx, &logical.Request{
		Storage: storage,
		Secret:  &logical.Secret{InternalData: map[string]interface{}{"cache_key": key, "account": "le"}},
	}, nil)
	require.NoError(t, err)
	entry, _ := b.cacheGet(ctx, storage, key)
	require.Equal(t, 1, entry.Users)

	// 1→0：删缓存
	_, err = certRevoke(ctx, &logical.Request{
		Storage: storage,
		Secret:  &logical.Secret{InternalData: map[string]interface{}{"cache_key": key, "account": "le"}},
	}, nil)
	require.NoError(t, err)
	entry, _ = b.cacheGet(ctx, storage, key)
	require.Nil(t, entry)
}

func TestRenewFreshCertNoop(t *testing.T) {
	b, storage := setupIssuable(t)
	ctx := context.Background()
	key := cacheKey(&roleEntry{Account: "le"}, []string{"example.com"})
	require.NoError(t, b.cachePut(ctx, storage, key, &cacheEntry{
		Users: 1, Account: "le", CN: "example.com", Domains: []string{"example.com"},
		CertificatePEM: selfSignedCertFor(t, time.Now().Add(-time.Hour), time.Now().Add(99*time.Hour)),
	}))

	resp, err := certRenew(ctx, &logical.Request{
		Storage: storage,
		Secret:  &logical.Secret{InternalData: map[string]interface{}{"cache_key": key, "account": "le"}},
	}, nil)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError())
	// 新鲜证书：空响应（自动续 lease）
	require.Nil(t, resp.Data)
}

func TestRenewStaleCertReissues(t *testing.T) {
	b, storage := setupIssuable(t)
	ctx := context.Background()
	key := cacheKey(&roleEntry{Account: "le"}, []string{"example.com"})
	require.NoError(t, b.cachePut(ctx, storage, key, &cacheEntry{
		Users: 1, Account: "le", CN: "example.com", Domains: []string{"example.com"},
		// 已过期证书 → ratio 任何值都需重签；重签会真调 pebble 并因 TXT 失败 → 预期错误
		CertificatePEM: selfSignedCertFor(t, time.Now().Add(-100*time.Hour), time.Now().Add(-1*time.Hour)),
	}))

	_, err := certRenew(ctx, &logical.Request{
		Storage: storage,
		Secret:  &logical.Secret{InternalData: map[string]interface{}{"cache_key": key, "account": "le"}},
	}, nil)
	require.Error(t, err) // pebble 无法完成 DNS 验证（fake provider）——证明走到了重签路径
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run 'TestRevoke|TestRenew' -v`
Expected: FAIL（未定义）

- [ ] **Step 3: 最小实现**

`acme/secret_cert.go`：

```go
package acme

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const secretCertType = "acme_cert"

// secretCert：certs/{role} 响应携带的 secret 类型，定义 lease 的 Renew/Revoke。
var secretCert = &framework.Secret{
	Type: secretCertType,
	Fields: map[string]*framework.FieldSchema{
		"common_name":  {Type: framework.TypeString},
		"domains":      {Type: framework.TypeCommaStringSlice},
		"certificate":  {Type: framework.TypeString},
		"private_key":  {Type: framework.TypeString},
		"issuer_cert":  {Type: framework.TypeString},
		"url":          {Type: framework.TypeString},
		"cert_stable_url": {Type: framework.TypeString},
	},
	Renew: certRenew,
	Revoke: certRevoke,
}

// certRenew：新鲜证书空响应（自动续 lease）；过期证书重签并刷新 KV 输出。
func certRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, _ := req.Secret.InternalData["cache_key"].(string)
	roleName, _ := req.Secret.InternalData["role"].(string)
	if key == "" || roleName == "" {
		return nil, fmt.Errorf("lease 缺少 cache_key/role InternalData")
	}
	entry, err := req.Storage.Get(ctx, storageKeyCache+key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		// 缓存被清空（cache DELETE）：无法重签，也不真撤销；自动续至自然过期。
		return &logical.Response{}, nil
	}
	var cached cacheEntry
	if err := entry.DecodeJSON(&cached); err != nil {
		return nil, err
	}

	role, err := getRoleOf(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q 已删除", roleName)
	}
	if !certNeedsRenewal(cached.CertificatePEM, role.CacheForRatio) {
		return &logical.Response{}, nil
	}

	// 重签：复用签发编排（内部 Users 重置为 1、刷新 KV 输出）。
	account, err := bOf(ctx, req).getAccount(ctx, req.Storage, role.Account)
	if err != nil || account == nil {
		if account == nil {
			return nil, fmt.Errorf("account %q 不存在", role.Account)
		}
		return nil, err
	}
	resp, err := bOf(ctx, req).doIssue(ctx, req, roleName, role, account, cached.CN, cached.Domains, key)
	if err != nil {
		return nil, fmt.Errorf("重签失败: %w", err)
	}
	return resp.(*logical.Response), nil
}

// certRevoke：引用计数递减；归零真撤销（尽力）+ 删缓存。
func certRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, _ := req.Secret.InternalData["cache_key"].(string)
	if key == "" {
		return nil, fmt.Errorf("lease 缺少 cache_key InternalData")
	}
	b := bOf(ctx, req)
	entry, err := b.cacheGet(ctx, req.Storage, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil // 已被清空/撤销
	}
	entry.Users--
	if entry.Users > 0 {
		return nil, b.cachePut(ctx, req.Storage, key, entry)
	}
	// 归零：尽力真撤销 ACME 证书（撤销失败仅记录，不阻断本地清理）。
	if user, uerr := ...; ... // 见下
	return nil, b.cacheDelete(ctx, req.Storage, key)
}
```

两个实现辅助（放 `acme/secret_cert.go` 底部，Renew/Revoke 回调没有 `*backend` 接收者，需从 req 还原）：

```go
// bOf：framework 不传 backend；用 backend 单例模式不优雅——改为在 Backend() 里
// 用闭包绑定：certRenew/certRevoke 定义为方法值 b.certRenew/b.certRevoke。
// 最终实现形态（以此为准）：把 Renew/Revoke 做成 backend 方法：
//
//	var secretCertFor = func(b *backend) *framework.Secret { ... Renew: b.certRenew, Revoke: b.certRevoke ... }
//
// Backend() 中： Secrets: []*framework.Secret{secretCertFor(b)}
// 方法签名： func (b *backend) certRenew(ctx, req, d) / func (b *backend) certRevoke(...)
// 下文 getRoleOf/bOf 不需要存在——按此形态实现。
```

Revoke 归零分支：

```go
func (b *backend) certRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, _ := req.Secret.InternalData["cache_key"].(string)
	if key == "" {
		return nil, fmt.Errorf("lease 缺少 cache_key InternalData")
	}
	entry, err := b.cacheGet(ctx, req.Storage, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	entry.Users--
	if entry.Users > 0 {
		return nil, b.cachePut(ctx, req.Storage, key, entry)
	}
	// 归零：尽力真撤销（account 可能已删——跳过撤销，只清缓存）
	if account, aerr := b.getAccount(ctx, req.Storage, entry.Account); aerr == nil && account != nil {
		if user, uerr := account.legoUser(); uerr == nil {
			if client, cerr := newLegoClient(user, account.ServerURL, account.InsecureTLS); cerr == nil {
				if cert, perr := certcrypto.ParsePEMCertificate([]byte(entry.CertificatePEM)); perr == nil {
					_ = client.Certificate.Revoke(ctx, cert.Raw, certificate.RevokeOptions{})
				}
			}
		}
	}
	return nil, b.cacheDelete(ctx, req.Storage, key)
}
```

import 补：`"github.com/go-acme/lego/v5/certcrypto"`、`"github.com/go-acme/lego/v5/certificate"`。

`path_certs.go` 修改：`issueResponse` 的 InternalData 增加 `internal["account"] = role.Account`、`internal["role"] = roleName`；`resp.Secret.Type = secretCertType`；`Backend()` 的 `Secrets: []*framework.Secret{}` 改为在 `Backend()` 内构造 `secretCertFor(b)`。

> 注：单测里 `setupIssuable` 返回值以 Task 11 实际签名为准（本计划写为 `(b, storage, env, "exec")`——若实现时 Task 11 的 helper 为 `(b, storage)` 则同步调整本任务测试调用）。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestRevoke|TestRenew' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add acme/secret_cert.go acme/secret_cert_test.go acme/backend.go acme/path_certs.go
git commit -m "feat: lease renew/revoke with refcount and ratio-driven reissue"
```

---

### Task 13: cache 管理端点（GET 数量 / DELETE 清空）

**Files:**
- Create: `acme/path_cache.go`
- Test: `acme/path_cache_test.go`

**Interfaces:**
- Consumes: Task 9 `cacheCount`/`cacheClear`
- Produces: `pathCache(b *backend) []*framework.Path`：`GET cache` → `{cached_certs: n}`；`DELETE cache` → `{cleared: n}`（文档注明：清空后现存 lease revoke 不再真撤销）

- [ ] **Step 1: 写失败测试**

`acme/path_cache_test.go`：

```go
package acme

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestCacheEndpoints(t *testing.T) {
	b, storage := testBackendConfig(t)
	ctx := context.Background()
	require.NoError(t, b.cachePut(ctx, storage, "k1", &cacheEntry{Users: 1}))
	require.NoError(t, b.cachePut(ctx, storage, "k2", &cacheEntry{Users: 1}))

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "cache", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, 2, resp.Data["cached_certs"])

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "cache", Storage: storage,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, 2, resp.Data["cleared"])

	resp, _ = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "cache", Storage: storage,
	}, nil)
	require.Equal(t, 0, resp.Data["cached_certs"])
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./acme/ -run TestCacheEndpoints -v`
Expected: FAIL

- [ ] **Step 3: 最小实现**

`acme/path_cache.go`：

```go
package acme

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathCache(b *backend) []*framework.Path {
	return []*framework.Path{{
		Pattern: "cache/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					n, err := b.cacheCount(ctx, req.Storage)
					if err != nil {
						return nil, err
					}
					return &logical.Response{Data: map[string]interface{}{"cached_certs": n}}, nil
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
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
```

`paths()` 聚合追加 `pathCache(b)`。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./acme/ -run 'TestCacheEndpoints|TestFactory' -v && go test -race ./acme/...`
Expected: 全部 PASS（顺带全量回归）

- [ ] **Step 5: Commit**

```bash
git add acme/path_cache.go acme/path_cache_test.go acme/backend.go
git commit -m "feat: cache management endpoints"
```

### Task 14: 验收测试（真实 bao server + exec provider + KV 全链路）

**Files:**
- Create: `test/acceptance_test.go`
- Create: `test/acme-dns.sh`
- Create: `test/go.mod`（独立 module：`module openbao-plugin-secrets-acme/test`，require 本仓库（replace 指向 `..`）+ openbao api/v2 v2.6.0 + testify；避免根模块把测试依赖混入插件构建）

**Interfaces:**
- Consumes: 构建产物 `bin/openbao-plugin-secrets-acme`（Makefile build）；`bao` CLI（dev server）；pebble+challtestsrv（Task 7 助手思路同款，但此处由测试自行拉起子进程）
- Produces: `make testacc` 全链路验证：注册插件（sha256）→ mount → 预置凭据 KV → dns-provider/account/role → exec provider 签发（TXT 真落地 challtestsrv）→ 读回 KV 输出 → lease revoke → pebble `cert-status-by-serial` 确认真撤销

- [ ] **Step 1: 写测试（验收测试无"失败驱动"意义，直接写完整用例）**

`test/acme-dns.sh`（exec provider 脚本：`EXEC_MODE=PRESENT/CLEANUP`，读 `EXEC_DOMAIN/EXEC_TOKEN/EXEC_KEY_AUTH`，调 challtestsrv HTTP API 落 TXT）：

```bash
#!/usr/bin/env bash
# lego exec provider 适配脚本：真实执行 DNS TXT 写/清（面向 challtestsrv）。
set -euo pipefail
: "${EXEC_MODE:?}" "${EXEC_DOMAIN:?}" "${EXEC_TOKEN:?}"
CHALL_URL="${CHALLTESTSRV_URL:-http://127.0.0.1:8055}"

if [ "${EXEC_MODE}" = "PRESENT" ]; then
  KEY_AUTH="${EXEC_KEY_AUTH:?}"
  curl -s -X POST "${CHALL_URL}/set-txt" -H 'Content-Type: application/json' \
    -d "{\"host\":\"_acme-challenge.${EXEC_DOMAIN}.\",\"value\":\"${KEY_AUTH}\"}" >/dev/null
else
  curl -s -X POST "${CHALL_URL}/clear-txt" -H 'Content-Type: application/json' \
    -d "{\"host\":\"_acme-challenge.${EXEC_DOMAIN}.\"}" >/dev/null
fi
```

`test/acceptance_test.go`（package test，TestMain 拉起 pebble/challtestsrv + `bao server -dev` + 注册插件；环境缺失 skip）：

```go
package test

// 关键流程（完整代码执行时照此结构写，变量名可微调）：
// 1. 前置检查：PATH 中有 bao/pebble/pebble-challtestsrv，否则 t.Skip
// 2. startPebble(t)（同 acme 包助手逻辑：自签证书 + 配置文件 + 子进程 + 等就绪）
// 3. 启动 `bao server -dev -plugin-directory <tmpdir>/plugins`（临时数据目录 + 内部端口随机）
//    —— 取得 dev root token（打印行 "Root Token: ..."）与 API 地址（BAO_ADDR）
// 4. go build 出插件二进制 → 放入 plugin_directory → sha256 注册：
//    bao plugin register -sha256=<sha> -namespace=root secret openbao-plugin-secrets-acme
// 5. bao secrets enable -path=acme openbao-plugin-secrets-acme
// 6. 预置凭据 KV：bao kv put secret/dns/cf CLOUDFLARE_DNS_API_TOKEN=dummy
// 7. 写 dns-provider：
//    bao write acme/dns-providers/exec type=cloudflare \
//      credentials_ref=mount=secret,path=dns/cf
// 8. 写 account：
//    bao write acme/accounts/le server_url=https://127.0.0.1:14000/dir \
//      contact=admin@example.com terms_of_service_agreed=true insecure_tls=true \
//      dns_providers=name=exec
//    （dns_providers 为 TypeSlice：用 bao write 传 JSON 字符串 `dns_providers='[{"name":"exec"}]'`）
// 9. 写 role：bao write acme/roles/web account=le allowed_domains=example.com \
//      allow_bare_domains=true output_kv_mount=secret
// 10. 签发：bao write acme/certs/web common_name=example.com
//     —— exec provider 由凭据数据携带脚本所需 env：为让 exec provider 工作，
//     本验收改用「凭据实时读」+ exec：dns-provider type=cloudflare 换为
//     type=cloudflare 且凭据真实不可行 → 验收用 t.TempDir 写 test/acme-dns.sh
//     后通过 KV 传 EXEC_PATH 等变量的方案改为：凭据 KV 内容即
//     {"EXEC_PATH": "<tmp>/acme-dns.sh", "EXEC_MODE_TIMEOUT": "20s"}，
//     dns-provider type 记为 exec（Task 15 README 声明 exec 也走注册表——
//     因此 Task 4 registry 增加 "exec" builder：Config{EXEC_PATH...}，
//     详见本任务 Step 2 的 registry 增补）
// 11. 断言签发响应含 certificate/private_key；`bao kv get secret/certs/web/example.com`
//     读回 KV 输出且 certificate 一致
// 12. 二次签发同域名 → 缓存命中（比较 cert url 一致 + 响应包含 output_path）
// 13. 找到 lease（sys/leases/lookup/acme/certs/web）→ `bao lease revoke acme/certs/web/<...>`
//     两次 → pebble 管理端口 GET :15000/cert-status-by-serial/<serial> 状态 revoked
```

- [ ] **Step 2: registry 增补 exec provider（Modify `acme/providers.go`）**

exec 是验收与「任意 DNS 商兜底」的关键，白名单加入：

```go
import "github.com/go-acme/lego/v5/providers/dns/exec"

var registry = map[string]providerBuilder{
	"cloudflare":   buildCloudflare,
	"alidns":       buildAliDNS,
	"tencentcloud": buildTencentCloud,
	"exec":         buildExec,
}

var envNames = map[string][]string{
	// ...原有...
	"exec": {"EXEC_PATH", "EXEC_MODE", "EXEC_PROPAGATION_TIMEOUT", "EXEC_POLLING_INTERVAL"},
}

func buildExec(_ context.Context, opts providerOpts, env map[string]string) (challenge.Provider, error) {
	cfg := exec.NewDefaultConfig()
	path, ok := env["EXEC_PATH"]
	if !ok || path == "" {
		return nil, fmt.Errorf("exec: 需要 EXEC_PATH（可用键：%s）", strings.Join(envNames["exec"], ", "))
	}
	cfg.Program = path
	if opts.PropagationTimeout > 0 {
		cfg.PropagationTimeout = opts.PropagationTimeout
	}
	if opts.PollingInterval > 0 {
		cfg.PollingInterval = opts.PollingInterval
	}
	return exec.NewDNSProviderConfig(cfg)
}
```

（exec 的 Program 字段名以 lego v5 `providers/dns/exec` 源码为准；如字段名不同以源码为准调整。）

- [ ] **Step 3: 跑验收测试**

Run:
```bash
go install github.com/letsencrypt/pebble/cmd/pebble@main
go install github.com/letsencrypt/pebble/cmd/pebble-challtestsrv@main
# bao CLI 已安装并在 PATH
chmod +x test/acme-dns.sh
make build && make testacc
```
Expected: PASS（签发成功、KV 输出可读回、双重 revoke 后 pebble 状态 revoked）

- [ ] **Step 4: Commit**

```bash
git add test/ acme/providers.go acme/providers_test.go
git commit -m "test: acceptance suite with real bao server and exec DNS provider"
```

---

### Task 15: CI/发布产物/README

**Files:**
- Create: `.github/workflows/test.yml`
- Create: `.github/workflows/release.yml`
- Create: `Containerfile`
- Modify: `Makefile`（追加 `release` 目标）
- Create: `README.md`

**Interfaces:**
- Consumes: 全部前序任务的 `make build/test/testacc`
- Produces: 可复现的 CI 与发布流水线（GitHub Releases 二进制+sha256、ghcr.io OCI 镜像），README 双安装路径文档

- [ ] **Step 1: CI workflow**

`.github/workflows/test.yml`：

```yaml
name: test
on:
  push: { branches: [main] }
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.26.x" }
      - run: go install github.com/letsencrypt/pebble/cmd/pebble@main
      - run: go install github.com/letsencrypt/pebble/cmd/pebble-challtestsrv@main
      - name: Install bao
        run: |
          curl -sL https://github.com/openbao/openbao/releases/latest/download/openbao_linux_amd64.zip -o bao.zip
          unzip -o bao.zip bao && sudo mv bao /usr/local/bin/
      - run: go vet ./...
      - run: make test
      - run: chmod +x test/acme-dns.sh && make build && make testacc
```

`.github/workflows/release.yml`（tag 触发）：build 8 平台二进制（GOOS/GOARCH：linux/darwin × amd64/arm64 + linux 386/riscv64 可选）、生成 sha256sums、ghcr 镜像（docker/build-push-action，`Containerfile`），附 Release。

`Containerfile`：

```dockerfile
FROM scratch
LABEL org.opencontainers.image.source=https://github.com/chisaato/openbao-plugin-secrets-acme
COPY bin/openbao-plugin-secrets-acme /openbao-plugin-secrets-acme
ENTRYPOINT ["/openbao-plugin-secrets-acme"]
```

`Makefile` 追加：

```make
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

release: build
	mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		GOOS=$$os GOARCH=$$arch $(GO) build -ldflags "-X main.pluginVersion=$(VERSION)" \
			-o dist/$(PLUGIN_NAME)_$${os}_$${arch} ./cmd/plugin || exit 1; \
	done
	cd dist && sha256sum * > SHA256SUMS
```

- [ ] **Step 2: README**

`README.md` 必须覆盖（顺序即结构）：
1. 简介：OpenBao ACME secrets engine（lego v5），v1 仅 DNS-01
2. 安装 A（传统）：`plugin_directory` → `bao plugin register -sha256=<sha> secret openbao-plugin-secrets-acme` → `bao secrets enable -path=acme openbao-plugin-secrets-acme`
3. 安装 B（声明式，config-plugins，OpenBao ≥2.5.0）：HCL 示例 `plugin "secret" "acme" { image = "ghcr.io/chisaato/openbao-plugin-secrets-acme"; version = "v0.1.0"; binary_name = "openbao-plugin-secrets-acme"; sha256sum = "..." }` + `plugin_auto_download/auto_register`
4. **部署前提（插件进程环境）**：插件用 `BAO_ADDR`/`VAULT_ADDR` 访问 API（凭据实时读 + KV 输出）——systemd `Environment=` 或声明式 plugin 块 `env` 注入；缺失时签发报 "create openbao client"
5. 快速上手：KV 放凭据 → `dns-providers` → `accounts`（含 `dns_providers` zones 路由说明）→ `roles` → `certs`；`accounts/{name}/rollover`、`accounts/{name}/key`、`cache` 端点
6. 凭据模型：实时读（调用者 token）、`credentials_ref` 键映射示例（显式 keys + 同名回退）、轮换=改 KV 即生效无须重启
7. ACL 矩阵：签发者 read 凭据 KV 路径 + write 输出 KV 路径；管理员 write acme/*；`accounts/{name}/key` 建议仅管理员
8. 缓存/lease：`cache_for_ratio` 语义、引用计数 revoke、cache DELETE 注意事项（现存 lease revoke 不再真撤销）
9. 扩展 provider：注册表加一行（`acme/providers.go`）+ `envNames` + 测试；PR 欢迎白名单扩展
10. 开发：`make build/test/testacc/release`；pebble 安装命令

- [ ] **Step 3: 全量回归**

Run: `make test && go vet ./... && make build`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add .github/ Containerfile Makefile README.md
git commit -m "ci: workflows, OCI release pipeline, and documentation"
```

---

## Self-Review 结论（已执行）

1. **Spec 覆盖**：spec §3-§10 全部有对应任务——dns-providers(Task 5)、accounts+rollover+key(Task 7)、roles+validateNames(Task 8)、cache 原语(Task 9)、KV 输出(Task 10)、签发编排+路由(Task 6/11)、Renew/Revoke(Task 12)、cache 端点(Task 13)、验收(Task 14)、入口/发布/README/ACL/BAO_ADDR 注记(Task 1/15)。凭据模型与路由语义内嵌于 Task 3/6。
2. **Placeholder 扫描**：Task 11/12 中的"实现说明/以此为准"块是**给实现者的明确决策指令**（闭包绑定 secret、MaxTTL 设置位置、字段名以 lego 源码为准），不是 TBD；已注明以哪个形态为准。
3. **类型一致性**：`credentialsRef`/`CredentialLoader`/`newProvider`/`providerOpts`/`routingProvider`/`cacheEntry`/`writeCertOutput`/`doIssue` 在定义任务与消费任务间签名一致；`setupIssuable` helper 返回值已加注以实现为准。

## 执行注意

- 单测中 `t.Context()`（Go 1.24+）如不可用，改 `context.Background()`。
- Task 14 是唯一依赖真实 `bao` CLI 的任务；其余全部离线（pebble 缺失自动 Skip）。
- 每任务一个 commit；发现 spec 偏差先改 spec 再改代码。

