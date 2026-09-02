package acme

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/api/v2"
)

// credentialsRef 描述一处 KV 凭据引用。Keys 左键为适配层所需的 lego
// 环境变量名，右值为用户 KV 数据中的实际键名；缺省时回退同名查找。
// mapstructure tag 供路径层 FieldData(map) WeakDecode 使用（如 kv_version）。
type credentialsRef struct {
	Mount     string            `json:"mount" mapstructure:"mount"`
	Path      string            `json:"path" mapstructure:"path"`
	KVVersion string            `json:"kv_version" mapstructure:"kv_version"`
	Version   int               `json:"version" mapstructure:"version"`
	Keys      map[string]string `json:"keys" mapstructure:"keys"`
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

	// version 0 表示读最新版本；>0 时按指定版本读取（KVv2）。
	var (
		secret *api.KVSecret
		verr   error
	)
	switch {
	case ref.kvVersion() == "1":
		secret, verr = client.KVv1(ref.Mount).Get(ctx, ref.Path)
		if verr != nil {
			return nil, fmt.Errorf("read kv1 %s/%s: %w", ref.Mount, ref.Path, verr)
		}
		if len(secret.Data) == 0 {
			// KVv1 空数据兜底：不静默返回空凭据。
			return nil, fmt.Errorf("credentials at %s/%s have been deleted (or contain no data)", ref.Mount, ref.Path)
		}
	case ref.Version > 0:
		secret, verr = client.KVv2(ref.Mount).GetVersion(ctx, ref.Path, ref.Version)
		if verr != nil {
			return nil, fmt.Errorf("read kv2 %s/data/%s (version %d): %w", ref.Mount, ref.Path, ref.Version, verr)
		}
		if len(secret.Data) == 0 {
			// KVv2 软删除：库不报错但 Data 为 nil，必须显式失败并定位凭据。
			return nil, fmt.Errorf("credentials at %s/data/%s (version %d) have been deleted (or contain no data)", ref.Mount, ref.Path, ref.Version)
		}
	default:
		secret, verr = client.KVv2(ref.Mount).Get(ctx, ref.Path)
		if verr != nil {
			return nil, fmt.Errorf("read kv2 %s/data/%s: %w", ref.Mount, ref.Path, verr)
		}
		if len(secret.Data) == 0 {
			// KVv2 软删除：库不报错但 Data 为 nil，必须显式失败并定位凭据。
			return nil, fmt.Errorf("credentials at %s/data/%s have been deleted (or contain no data)", ref.Mount, ref.Path)
		}
	}
	data := secret.Data

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
