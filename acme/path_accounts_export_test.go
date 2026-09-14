package acme

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	storagemod "github.com/chisaato/openbao-plugin-secrets-acme/pkg/storage"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

// putExportAccount 直接向存储写入一个带合法 EC256 私钥与注册信息的账户条目。
func putExportAccount(t *testing.T, s logical.Storage, name, contact string) *accountEntry {
	t.Helper()
	_, pemStr, err := generatePrivateKeyPEM(keyTypes["EC256"])
	require.NoError(t, err)
	e := &accountEntry{
		Name:             name,
		ServerURL:        "https://example.test/dir",
		Contact:          contact,
		TOSAgreed:        true,
		KeyType:          "EC256",
		PrivateKeyPEM:    pemStr,
		RegistrationJSON: `{"status":"valid","uri":"https://example/acct/1"}`,
	}
	require.NoError(t, storagemod.PutAccount(context.Background(), s, name, e))
	return e
}

func TestAccountExport(t *testing.T) {
	ctx := context.Background()
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	e := putExportAccount(t, s, "le", "admin@example.com")

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/le/export", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	// 键名须与 api.AccountExport 契约一致。
	require.Equal(t, api.AccountExportKind, resp.Data["kind"])
	require.Equal(t, api.AccountExportVersion, resp.Data["version"])
	require.Equal(t, "le", resp.Data["name"])
	require.Equal(t, e.ServerURL, resp.Data["server_url"])
	require.Equal(t, e.Contact, resp.Data["contact"])
	require.Equal(t, e.TOSAgreed, resp.Data["terms_of_service_agreed"])
	require.Equal(t, e.KeyType, resp.Data["key_type"])
	require.Equal(t, e.PrivateKeyPEM, resp.Data["private_key_pem"])
	require.Equal(t, e.RegistrationJSON, resp.Data["registration_json"])

	// 不存在的账户 → 空响应（映射为 404）。
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/missing/export", Storage: s,
	})
	require.NoError(t, err)
	require.Nil(t, resp)
}

// importData 构造一份合法导入载荷，供各用例按需篡改。
func importData(t *testing.T) map[string]interface{} {
	t.Helper()
	_, pemStr, err := generatePrivateKeyPEM(keyTypes["EC256"])
	require.NoError(t, err)
	return map[string]interface{}{
		"server_url":        "https://example.test/dir",
		"contact":           "admin@example.com",
		"key_type":          "EC256",
		"private_key_pem":   pemStr,
		"registration_json": `{"status":"valid","uri":"https://example/acct/1"}`,
	}
}

func TestAccountImport(t *testing.T) {
	ctx := context.Background()
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	data := importData(t)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/imported/import",
		Storage: s, Data: data,
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "import: %v", resp)
	// 未开启 verify 时纯本地恢复。
	require.Equal(t, false, resp.Data["verified"])
	require.Equal(t, false, resp.Data["overwritten"])
	require.Equal(t, "imported", resp.Data["name"])
	require.Equal(t, "https://example.test/dir", resp.Data["server_url"])
	require.Equal(t, "EC256", resp.Data["key_type"])

	// 落盘内容与载荷一致。
	e, err := storagemod.GetAccount(ctx, s, "imported")
	require.NoError(t, err)
	require.NotNil(t, e)
	require.Equal(t, "imported", e.Name)
	require.Equal(t, "admin@example.com", e.Contact)
	require.Equal(t, data["private_key_pem"], e.PrivateKeyPEM)
	require.Equal(t, data["registration_json"], e.RegistrationJSON)
	require.Equal(t, "EC256", e.KeyType)
}

func TestAccountImportValidation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		mutate func(map[string]interface{})
		want   string
	}{
		{"缺 server_url", func(d map[string]interface{}) { d["server_url"] = "" }, "server_url 必填"},
		{"缺 private_key_pem", func(d map[string]interface{}) { d["private_key_pem"] = "" }, "private_key_pem 必填"},
		{"缺 registration_json", func(d map[string]interface{}) { d["registration_json"] = "" }, "registration_json 必填"},
		{"缺 key_type", func(d map[string]interface{}) { d["key_type"] = "" }, "key_type 必填"},
		{"非法 key_type", func(d map[string]interface{}) { d["key_type"] = "RSA1024" }, "key_type 必须"},
		{"非法 PEM", func(d map[string]interface{}) { d["private_key_pem"] = "not-a-pem" }, "private_key_pem 解析失败"},
		{"非法 registration_json", func(d map[string]interface{}) { d["registration_json"] = "{not-json" }, "registration_json 解析失败"},
		{"引用的 dns-provider 不存在", func(d map[string]interface{}) {
			d["dns_providers"] = []interface{}{map[string]interface{}{"name": "missing"}}
		}, "不存在"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, s := testBackend(t, NewFakeCredentialLoader(nil))
			data := importData(t)
			tc.mutate(data)
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation, Path: "accounts/bad/import",
				Storage: s, Data: data,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.True(t, resp.IsError(), "期望错误响应，得到 %v", resp)
			require.Contains(t, resp.Error().Error(), tc.want)
		})
	}
}

func TestAccountImportOverwrite(t *testing.T) {
	ctx := context.Background()
	b, s := testBackend(t, NewFakeCredentialLoader(nil))
	putExportAccount(t, s, "dup", "old@example.com")

	// 重名且不带 overwrite → 拒绝。
	data := importData(t)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/dup/import",
		Storage: s, Data: data,
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "已存在")

	// 带 overwrite → 覆盖成功。
	data["overwrite"] = true
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/dup/import",
		Storage: s, Data: data,
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "overwrite import: %v", resp)
	require.Equal(t, true, resp.Data["overwritten"])

	e, err := storagemod.GetAccount(ctx, s, "dup")
	require.NoError(t, err)
	require.NotNil(t, e)
	require.Equal(t, "admin@example.com", e.Contact)
}

// TestAccountImportVerifyWithPebble 复用 pebble harness：先注册并导出，再以
// verify=true 导入到新名字，确认私钥已注册且 registration_json 被 CA 返回刷新。
func TestAccountImportVerifyWithPebble(t *testing.T) {
	env := startPebble(t)
	ctx := context.Background()
	b, s := testBackend(t, NewFakeCredentialLoader(nil))

	// 在 pebble 注册源账户。
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/src",
		Storage: s, Data: accountData(env.DirURL),
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "create source: %v", resp)

	// 导出后回灌到新账户名。
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "accounts/src/export", Storage: s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	exported := resp.Data

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "accounts/dst/import",
		Storage: s,
		Data: map[string]interface{}{
			"server_url":              exported["server_url"],
			"contact":                 exported["contact"],
			"terms_of_service_agreed": exported["terms_of_service_agreed"],
			"key_type":                exported["key_type"],
			"private_key_pem":         exported["private_key_pem"],
			"registration_json":       exported["registration_json"],
			"insecure_tls":            true,
			"verify":                  true,
		},
	})
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "import verify: %v", resp)
	require.Equal(t, true, resp.Data["verified"])
	require.Equal(t, false, resp.Data["overwritten"])

	e, err := storagemod.GetAccount(ctx, s, "dst")
	require.NoError(t, err)
	require.NotNil(t, e)
	require.Equal(t, "dst", e.Name)
	require.True(t, e.InsecureTLS)
	// CA 返回的注册信息已刷新为合法 JSON。
	var reg map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(e.RegistrationJSON), &reg))
	require.NotEmpty(t, reg)
}
