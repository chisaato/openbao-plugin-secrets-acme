package cmd

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/client"
	"github.com/spf13/cobra"
)

// writeDNSProvider 以扁平标量凭据字段写入 dns-providers/{name}。
// 插件新 API 优先接受 credentials_mount / credentials_path（credentials_ref 对象
// 形态仅在读取兼容路径保留），因此这里不再复用会发出嵌套对象的 Client.SetDNSProvider。
func writeDNSProvider(ctx context.Context, cli *client.Client, name string, p api.DNSProvider, credMount, credPath string) error {
	data := map[string]any{
		"type":              p.Type,
		"credentials_mount": credMount,
		"credentials_path":  credPath,
	}
	if p.PropagationTimeout > 0 {
		data["propagation_timeout"] = p.PropagationTimeout.String()
	}
	if p.PollingInterval > 0 {
		data["polling_interval"] = p.PollingInterval.String()
	}
	if p.SkipPropagationCheck {
		data["skip_propagation_check"] = p.SkipPropagationCheck
	}
	if p.PropagationWait > 0 {
		data["propagation_wait"] = p.PropagationWait
	}
	if len(p.Resolvers) > 0 {
		data["resolvers"] = p.Resolvers
	}

	mount := strings.Trim(FlagMount, "/")
	logicalPath := path.Join(mount, "dns-providers/"+name)
	_, err := cli.RawClient().Logical().WriteWithContext(ctx, logicalPath, data)
	return err
}

func NewProviderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provider",
		Short: "DNS-01 Provider 凭据与配置管理",
	}

	var (
		pType           string
		credMount       string
		credPath        string
		propTimeout     string
		pollInterval    string
		skipPropagation bool
		propWait        int
		pResolvers      []string
	)

	setCmd := &cobra.Command{
		Use:   "set <name>",
		Short: "配置或更新 DNS Provider (支持单独字段增量覆盖)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cli, err := GetClient()
			if err != nil {
				return err
			}

			// 尝试读取已有 Provider 配置以支持增量覆盖
			var p api.DNSProvider
			existing, getErr := cli.GetDNSProvider(cmd.Context(), name)
			if getErr == nil && existing != nil {
				p = *existing
			}

			// 仅更新用户在命令行中显式声明了的字段 (Changed)
			if cmd.Flags().Changed("type") {
				p.Type = pType
			}

			// 解析凭据引用（扁平标量）：存量 mount/path 仅在对应 flag 未显式覆盖时沿用，
			// 保证增量更新不会丢失既有凭据信息，也不会用空值覆盖。
			mount := credMount
			if mount == "" {
				mount = "secret"
			}
			if !cmd.Flags().Changed("cred-mount") && p.CredentialsRef != nil {
				mount = p.CredentialsRef.Mount
			}
			credPathVal := credPath
			if !cmd.Flags().Changed("cred-path") && p.CredentialsRef != nil {
				credPathVal = p.CredentialsRef.Path
			}
			if cmd.Flags().Changed("prop-timeout") {
				d, err := time.ParseDuration(propTimeout)
				if err != nil {
					return fmt.Errorf("非法 propagation-timeout: %w", err)
				}
				p.PropagationTimeout = d
			}
			if cmd.Flags().Changed("poll-interval") {
				d, err := time.ParseDuration(pollInterval)
				if err != nil {
					return fmt.Errorf("非法 polling-interval: %w", err)
				}
				p.PollingInterval = d
			}
			if cmd.Flags().Changed("skip-check") {
				p.SkipPropagationCheck = skipPropagation
			}
			if cmd.Flags().Changed("prop-wait") {
				p.PropagationWait = propWait
			}
			if cmd.Flags().Changed("resolvers") {
				p.Resolvers = pResolvers
			}

			if p.Type == "" {
				return fmt.Errorf("全新配置 DNS Provider 时 --type 为必填项")
			}
			if credPathVal == "" {
				return fmt.Errorf("全新配置 DNS Provider 时 --cred-path 为必填项")
			}

			if err := writeDNSProvider(cmd.Context(), cli, name, p, mount, credPathVal); err != nil {
				return err
			}
			fmt.Printf("DNS Provider %q 配置成功\n", name)
			return nil
		},
	}
	setCmd.Flags().StringVar(&pType, "type", "", "Provider 类型 (如 alidns, tencentcloud, cloudflare)")
	setCmd.Flags().StringVar(&credMount, "cred-mount", "secret", "凭据所在的 KV mount")
	setCmd.Flags().StringVar(&credPath, "cred-path", "", "凭据所在的 KV 相对路径")
	setCmd.Flags().StringVar(&propTimeout, "prop-timeout", "2m", "DNS 传播超时")
	setCmd.Flags().StringVar(&pollInterval, "poll-interval", "2s", "DNS 轮询间隔")
	setCmd.Flags().BoolVar(&skipPropagation, "skip-check", false, "跳过预检 (适用于本地 pebble 或自建权威 DNS)")
	setCmd.Flags().IntVar(&propWait, "prop-wait", 0, "跳过预检时的固定等待秒数")
	setCmd.Flags().StringSliceVar(&pResolvers, "resolvers", nil, "自定义递归 DNS 解析服务器 (例如 223.5.5.5:53,1.1.1.1:53)")

	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "获取 DNS Provider 配置",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			p, err := cli.GetDNSProvider(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			PrintOutput(p)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出全部 DNS Provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			list, err := cli.ListDNSProviders(cmd.Context())
			if err != nil {
				return err
			}
			if FlagFormat == "json" {
				PrintOutput(list)
				return nil
			}
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "未找到任何 DNS Provider。")
				return nil
			}

			tw := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(tw, "NAME\tTYPE\tTIMEOUT\tINTERVAL\tPROP_WAIT\tRESOLVERS")
			for _, name := range list {
				p, err := cli.GetDNSProvider(cmd.Context(), name)
				if err != nil {
					fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t-\n", name)
					continue
				}
				resStr := strings.Join(p.Resolvers, ", ")
				if resStr == "" {
					resStr = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%ds\t%s\n",
					name, p.Type, p.PropagationTimeout, p.PollingInterval, p.PropagationWait, resStr)
			}
			_ = tw.Flush()
			return nil
		},
	}

	delCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "删除 DNS Provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			if err := cli.DeleteDNSProvider(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Printf("DNS Provider %q 已删除\n", args[0])
			return nil
		},
	}

	renameCmd := &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "重命名 DNS Provider（本地改名并迁移 account 引用）",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			res, err := cli.RenameDNSProvider(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			if FlagFormat == "json" {
				PrintOutput(res)
			} else {
				fmt.Printf("DNS Provider %q 已改名为 %q (迁移 accounts=%d)\n",
					res.OldName, res.NewName, res.MigratedAccounts)
			}
			return nil
		},
	}

	cmd.AddCommand(setCmd, getCmd, listCmd, delCmd, renameCmd)
	return cmd
}
