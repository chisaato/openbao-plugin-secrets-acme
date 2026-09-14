package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/spf13/cobra"
)

func NewAccountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "ACME 账户管理",
	}

	var (
		serverURL   string
		contact     string
		tosAgreed   bool
		keyType     string
		insecureTLS bool
		providers   []string
	)

	regCmd := &cobra.Command{
		Use:   "register <name>",
		Short: "向 ACME CA 注册新账户",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cli, err := GetClient()
			if err != nil {
				return err
			}
			var pRefs []api.DNSProviderRef
			for _, p := range providers {
				parts := strings.SplitN(p, ":", 2)
				ref := api.DNSProviderRef{Name: parts[0]}
				if len(parts) > 1 && parts[1] != "" {
					ref.Zones = strings.Split(parts[1], ",")
				}
				pRefs = append(pRefs, ref)
			}
			acc, err := cli.RegisterAccount(cmd.Context(), name, api.Account{
				ServerURL:    serverURL,
				Contact:      contact,
				TOSAgreed:    tosAgreed,
				KeyType:      keyType,
				InsecureTLS:  insecureTLS,
				DNSProviders: pRefs,
			})
			if err != nil {
				return fmt.Errorf("注册账户失败: %w", err)
			}
			if FlagFormat == "json" {
				PrintOutput(acc)
			} else {
				fmt.Printf("账户 %q 注册成功 (CA: %s)\n", name, acc.ServerURL)
			}
			return nil
		},
	}
	regCmd.Flags().StringVar(&serverURL, "server-url", "", "ACME Directory URL (必填)")
	regCmd.Flags().StringVar(&contact, "contact", "", "联系方式 (如 mailto:admin@example.com，必填)")
	regCmd.Flags().BoolVar(&tosAgreed, "agree-tos", true, "同意服务条款")
	regCmd.Flags().StringVar(&keyType, "key-type", "EC256", "私钥类型 (EC256, EC384, RSA2048, RSA4096)")
	regCmd.Flags().BoolVar(&insecureTLS, "insecure-tls", false, "跳过 CA TLS 证书校验 (测试用)")
	regCmd.Flags().StringSliceVar(&providers, "provider", nil, "关联 DNS Provider，格式 'name' 或 'name:zone1,zone2'")
	_ = regCmd.MarkFlagRequired("server-url")
	_ = regCmd.MarkFlagRequired("contact")

	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "获取账户详情",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			acc, err := cli.GetAccount(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			PrintOutput(acc)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出全部已注册的 ACME 账户",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			list, err := cli.ListAccounts(cmd.Context())
			if err != nil {
				return err
			}
			if FlagFormat == "json" {
				PrintOutput(list)
				return nil
			}
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "未找到任何账户。")
				return nil
			}

			tw := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(tw, "NAME\tSERVER URL\tCONTACT\tKEY TYPE\tPROVIDERS")
			for _, name := range list {
				acc, err := cli.GetAccount(cmd.Context(), name)
				if err != nil {
					fmt.Fprintf(tw, "%s\t-\t-\t-\t-\n", name)
					continue
				}
				var pNames []string
				for _, p := range acc.DNSProviders {
					pNames = append(pNames, p.Name)
				}
				pStr := strings.Join(pNames, ", ")
				if pStr == "" {
					pStr = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					name, acc.ServerURL, acc.Contact, acc.KeyType, pStr)
			}
			_ = tw.Flush()
			return nil
		},
	}

	deactCmd := &cobra.Command{
		Use:   "deactivate <name>",
		Short: "注销/删除 ACME 账户",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			if err := cli.DeactivateAccount(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Printf("账户 %q 已注销并删除\n", args[0])
			return nil
		},
	}

	renameCmd := &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "重命名 ACME 账户（本地改名并迁移引用）",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			res, err := cli.RenameAccount(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			if FlagFormat == "json" {
				PrintOutput(res)
			} else {
				fmt.Printf("账户 %q 已改名为 %q (迁移 roles=%d jobs=%d certs=%d)\n",
					res.OldName, res.NewName, res.MigratedRoles, res.MigratedJobs, res.MigratedCerts)
				for _, w := range res.Warnings {
					fmt.Printf("警告: %s\n", w)
				}
			}
			return nil
		},
	}

	var (
		exportOut string
	)
	exportCmd := &cobra.Command{
		Use:   "export <name>",
		Short: "导出账户（含私钥，可跨实例复用）",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cli, err := GetClient()
			if err != nil {
				return err
			}
			exp, err := cli.ExportAccount(cmd.Context(), name)
			if err != nil {
				return fmt.Errorf("导出账户失败: %w", err)
			}
			b, err := json.MarshalIndent(exp, "", "  ")
			if err != nil {
				return fmt.Errorf("序列化导出内容失败: %w", err)
			}
			b = append(b, '\n')
			if exportOut == "" {
				// 未指定输出文件时直接打印到标准输出
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			// 含私钥，权限收紧为 0600
			if err := os.WriteFile(exportOut, b, 0o600); err != nil {
				return fmt.Errorf("写入导出文件失败: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "账户 %q 已导出到 %s（含私钥，请妥善保管）\n", name, exportOut)
			return nil
		},
	}
	exportCmd.Flags().StringVarP(&exportOut, "out", "o", "", "导出文件路径（省略则打印到标准输出）")

	var (
		importFile  string
		overwrite   bool
		verify      bool
		impInsecTLS bool
		impProvider []string
	)
	importCmd := &cobra.Command{
		Use:   "import <name>",
		Short: "从导出文件导入账户",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			raw, err := os.ReadFile(importFile)
			if err != nil {
				return fmt.Errorf("读取导入文件失败: %w", err)
			}
			var exp api.AccountExport
			if err := json.Unmarshal(raw, &exp); err != nil {
				return fmt.Errorf("解析导入文件失败: %w", err)
			}
			if exp.Kind != api.AccountExportKind {
				return fmt.Errorf("不是有效的账户导出文件")
			}
			if exp.Version != api.AccountExportVersion {
				return fmt.Errorf("导出文件版本过新，请升级 CLI")
			}
			if exp.Name != "" && exp.Name != name {
				fmt.Fprintf(cmd.OutOrStdout(), "源账户名 %q，将导入为 %q\n", exp.Name, name)
			}

			cli, err := GetClient()
			if err != nil {
				return err
			}
			// 复用 register 的 'name[:zone1,zone2]' 解析逻辑
			var pRefs []api.DNSProviderRef
			for _, p := range impProvider {
				parts := strings.SplitN(p, ":", 2)
				ref := api.DNSProviderRef{Name: parts[0]}
				if len(parts) > 1 && parts[1] != "" {
					ref.Zones = strings.Split(parts[1], ",")
				}
				pRefs = append(pRefs, ref)
			}
			res, err := cli.ImportAccount(cmd.Context(), name, &exp, api.AccountImportOptions{
				Overwrite:   overwrite,
				Verify:      verify,
				InsecureTLS: impInsecTLS,
			}, pRefs)
			if err != nil {
				return fmt.Errorf("导入账户失败: %w", err)
			}
			if FlagFormat == "json" {
				PrintOutput(res)
				return nil
			}
			msg := fmt.Sprintf("账户 %q 已导入 (CA: %s)", name, res.ServerURL)
			if verify {
				msg += " 已向 CA 验证"
			}
			if overwrite {
				msg += "（覆盖已有账户）"
			}
			fmt.Fprintln(cmd.OutOrStdout(), msg)
			return nil
		},
	}
	importCmd.Flags().StringVar(&importFile, "file", "", "导出文件路径 (必填)")
	importCmd.Flags().BoolVar(&overwrite, "overwrite", false, "目标账户名已存在时允许覆盖")
	importCmd.Flags().BoolVar(&verify, "verify", false, "导入前向 CA 验证私钥并刷新注册信息")
	importCmd.Flags().BoolVar(&impInsecTLS, "insecure-tls", false, "跳过 CA TLS 证书校验 (测试用)")
	importCmd.Flags().StringSliceVar(&impProvider, "provider", nil, "导入时绑定 DNS Provider，格式 'name' 或 'name:zone1,zone2'")
	_ = importCmd.MarkFlagRequired("file")

	cmd.AddCommand(regCmd, getCmd, listCmd, deactCmd, renameCmd, exportCmd, importCmd)
	return cmd
}
