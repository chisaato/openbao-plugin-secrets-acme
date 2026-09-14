package cmd

import (
	"fmt"
	"os"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/client"
	"github.com/spf13/cobra"
)

var (
	FlagAddress string
	FlagToken   string
	FlagMount   string
	FlagFormat  string

	RootCmd = NewRootCmd()
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bao-acme",
		Short: "OpenBao ACME 插件运维与证书签发 CLI",
		Long: `bao-acme 是用于与 openbao-plugin-secrets-acme 交互的命令行工具。
支持账户管理、DNS Provider 配置、Role 策略制定、异步证书签发及 Job 状态轮询。`,
	}

	cmd.PersistentFlags().StringVar(&FlagAddress, "address", "", "OpenBao 服务地址 (默认从 BAO_ADDR/VAULT_ADDR 读取，或 http://127.0.0.1:8200)")
	cmd.PersistentFlags().StringVar(&FlagToken, "token", "", "OpenBao 访问 Token (默认依次从 BAO_TOKEN/VAULT_TOKEN、以及 bao CLI token helper 即 ~/.vault-token 读取，后者为 bao CLI 登录后的 token 缓存位置，认证方式不限)")
	cmd.PersistentFlags().StringVar(&FlagMount, "mount", "acme", "ACME 插件挂载路径")
	cmd.PersistentFlags().StringVarP(&FlagFormat, "format", "f", "text", "输出格式 (text 或 json)")

	cmd.AddCommand(NewAccountCmd())
	cmd.AddCommand(NewProviderCmd())
	cmd.AddCommand(NewRoleCmd())
	cmd.AddCommand(NewCertCmd())
	cmd.AddCommand(NewJobCmd())

	return cmd
}

func GetClient() (*client.Client, error) {
	return client.NewClient(client.Config{
		Address: FlagAddress,
		Token:   FlagToken,
		Mount:   FlagMount,
	})
}

func PrintOutput(data any) {
	if FlagFormat == "json" {
		s, err := client.FormatJSON(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "格式化 JSON 失败: %v\n", err)
			return
		}
		fmt.Println(s)
		return
	}

	switch v := data.(type) {
	case string:
		fmt.Println(v)
	case []string:
		for _, item := range v {
			fmt.Println(item)
		}
	default:
		s, _ := client.FormatJSON(data)
		fmt.Println(s)
	}
}
