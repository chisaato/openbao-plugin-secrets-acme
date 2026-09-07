package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func NewRoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "证书签发 Role 策略管理",
	}

	var (
		account          string
		allowedDomains   []string
		allowBare        bool
		allowSub         bool
		allowAny         bool
		disableCache     bool
		disableCertReuse bool
		cacheForRatio    int
		outputKVMount    string
	)

	setCmd := &cobra.Command{
		Use:   "set <name>",
		Short: "创建或覆盖更新 Role (仅传递被指定的 flag，未指定的保留旧值)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cli, err := GetClient()
			if err != nil {
				return err
			}

			// 收集用户在命令行实际传递改变的 flag
			fields := make(map[string]any)
			if cmd.Flags().Changed("account") {
				fields["account"] = account
			}
			if cmd.Flags().Changed("allowed-domains") {
				fields["allowed_domains"] = allowedDomains
			}
			if cmd.Flags().Changed("allow-bare") {
				fields["allow_bare_domains"] = allowBare
			}
			if cmd.Flags().Changed("allow-sub") {
				fields["allow_subdomains"] = allowSub
			}
			if cmd.Flags().Changed("allow-any") {
				fields["allow_any_name"] = allowAny
			}
			if cmd.Flags().Changed("disable-cache") {
				fields["disable_cache"] = disableCache
			}
			if cmd.Flags().Changed("disable-reuse") {
				fields["disable_cert_reuse"] = disableCertReuse
			}
			if cmd.Flags().Changed("cache-ratio") {
				fields["cache_for_ratio"] = cacheForRatio
			}
			if cmd.Flags().Changed("output-kv") {
				fields["output_kv_mount"] = outputKVMount
			}

			if len(fields) == 0 {
				return fmt.Errorf("未指定任何需要设置的字段，请参考 --help")
			}

			if err := cli.UpdateRole(cmd.Context(), name, fields); err != nil {
				return err
			}
			fmt.Printf("Role %q 配置成功\n", name)
			return nil
		},
	}
	setCmd.Flags().StringVar(&account, "account", "", "关联的 ACME 账户名 (首次创建时必填)")
	setCmd.Flags().StringSliceVar(&allowedDomains, "allowed-domains", nil, "白名单根域名 (逗号分隔)")
	setCmd.Flags().BoolVar(&allowBare, "allow-bare", false, "允许白名单裸域 (--allow-bare / --allow-bare=false)")
	setCmd.Flags().BoolVar(&allowSub, "allow-sub", false, "允许白名单子域 (--allow-sub / --allow-sub=false)")
	setCmd.Flags().BoolVar(&allowAny, "allow-any", false, "允许任意域名签发 (--allow-any / --allow-any=false)")
	setCmd.Flags().BoolVar(&disableCache, "disable-cache", false, "禁用证书缓存 (--disable-cache / --disable-cache=false)")
	setCmd.Flags().BoolVar(&disableCertReuse, "disable-reuse", false, "禁用泛域名覆盖复用 (--disable-reuse / --disable-reuse=false)")
	setCmd.Flags().IntVar(&cacheForRatio, "cache-ratio", 0, "缓存有效期百分比 (1-100)")
	setCmd.Flags().StringVar(&outputKVMount, "output-kv", "", "输出证书与私钥的 KV-v2 挂载路径 (如 secret)")

	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "获取 Role 详情",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			r, err := cli.GetRole(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			PrintOutput(r)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出全部 Role",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			list, err := cli.ListRoles(cmd.Context())
			if err != nil {
				return err
			}
			if FlagFormat == "json" {
				PrintOutput(list)
				return nil
			}
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "未找到任何 Role。")
				return nil
			}

			tw := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(tw, "ROLE\tACCOUNT\tALLOWED DOMAINS\tRATIO\tDISABLE_CACHE\tKV_MOUNT")
			for _, name := range list {
				role, err := cli.GetRole(cmd.Context(), name)
				if err != nil {
					fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t-\n", name)
					continue
				}
				domainsStr := strings.Join(role.AllowedDomains, ", ")
				if domainsStr == "" {
					domainsStr = "-"
				}
				kvMount := role.OutputKVMount
				if kvMount == "" {
					kvMount = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d%%\t%v\t%s\n",
					name, role.Account, domainsStr, role.CacheForRatio, role.DisableCache, kvMount)
			}
			_ = tw.Flush()
			return nil
		},
	}

	delCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "删除 Role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			if err := cli.DeleteRole(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Printf("Role %q 已删除\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(setCmd, getCmd, listCmd, delCmd)
	return cmd
}
