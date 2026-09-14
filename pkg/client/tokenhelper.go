package client

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	baoapi "github.com/openbao/openbao/api/v2"
)

// baoConfigPath 返回 bao CLI 配置文件的路径。
// 优先取 BAO_CONFIG_PATH（含 VAULT_CONFIG_PATH 回退），否则默认 ~/.bao。
func baoConfigPath() string {
	if v := baoapi.ReadBaoVariable("BAO_CONFIG_PATH"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".bao"
	}
	return filepath.Join(home, ".bao")
}

// expandTilde 将路径前缀 ~ 展开为当前用户家目录。
func expandTilde(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// readTokenHelperConfig 读取 bao CLI 配置中的 token_helper。
// 配置文件不存在或解析失败时返回空串（视为未配置外部 helper），不中断流程。
func readTokenHelperConfig() string {
	contents, err := os.ReadFile(expandTilde(baoConfigPath()))
	if err != nil {
		return ""
	}
	var cfg struct {
		TokenHelper string `hcl:"token_helper"`
	}
	if err := hcl.Decode(&cfg, string(contents)); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.TokenHelper)
}

// tokenFromExternalHelper 执行外部 token helper 的 get 操作获取 token。
// 命令按空格切分，首段为可执行文件，其余为前置参数，末尾追加 "get"。
// 执行时注入 BAO_ADDR / VAULT_ADDR 指向当前 bao 服务地址。
func tokenFromExternalHelper(helper string, addr string) (string, error) {
	fields := strings.Fields(helper)
	if len(fields) == 0 {
		return "", nil
	}

	bin := expandTilde(fields[0])
	args := append(append([]string{}, fields[1:]...), "get")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(),
		"BAO_ADDR="+addr,
		"VAULT_ADDR="+addr,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("执行外部 token helper %q 失败: %s: %w", helper, strings.TrimSpace(stderr.String()), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// tokenFromInternalHelper 从内部文件 helper 读取 token。
// 路径优先取 BAO_TOKEN_PATH，否则默认 ~/.vault-token；文件不存在不算错误，返回空串。
func tokenFromInternalHelper() (string, error) {
	path := baoapi.ReadBaoVariable(baoapi.EnvTokenPath)
	if path == "" {
		path = expandTilde("~/.vault-token")
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(contents)), nil
}

// tokenFromBaoHelper 读取 bao CLI token helper 中保存的 token。
// 返回空串表示 helper 中没有 token。addr 为当前 bao 服务地址。
func tokenFromBaoHelper(addr string) (string, error) {
	// 优先使用配置的外部 helper，未配置时回退到内部文件 helper。
	if helper := readTokenHelperConfig(); helper != "" {
		return tokenFromExternalHelper(helper, addr)
	}
	return tokenFromInternalHelper()
}
