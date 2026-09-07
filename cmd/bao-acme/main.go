package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/client"
	"github.com/spf13/cobra"
)

var (
	flagAddress string
	flagToken   string
	flagMount   string
	flagFormat  string

	rootCmd = &cobra.Command{
		Use:   "bao-acme",
		Short: "OpenBao ACME 插件运维与证书签发 CLI",
		Long: `bao-acme 是用于与 openbao-plugin-secrets-acme 交互的命令行工具。
支持账户管理、DNS Provider 配置、Role 策略制定、异步证书签发及 Job 状态轮询。`,
	}
)

func newRootCmd() *cobra.Command {
	var (
		localAddress string
		localToken   string
		localMount   string
		localFormat  string
	)

	cmd := &cobra.Command{
		Use:   "bao-acme",
		Short: "OpenBao ACME 插件运维与证书签发 CLI",
		Long: `bao-acme 是用于与 openbao-plugin-secrets-acme 交互的命令行工具。
支持账户管理、DNS Provider 配置、Role 策略制定、异步证书签发及 Job 状态轮询。`,
	}

	cmd.PersistentFlags().StringVar(&flagAddress, "address", "", "OpenBao 服务地址 (默认从 BAO_ADDR/VAULT_ADDR 读取，或 http://127.0.0.1:8200)")
	cmd.PersistentFlags().StringVar(&flagToken, "token", "", "OpenBao 访问 Token (默认从 BAO_TOKEN/VAULT_TOKEN 读取)")
	cmd.PersistentFlags().StringVar(&flagMount, "mount", "acme", "ACME 插件挂载路径")
	cmd.PersistentFlags().StringVarP(&flagFormat, "format", "f", "text", "输出格式 (text 或 json)")

	cmd.AddCommand(newAccountCmd())
	cmd.AddCommand(newProviderCmd())
	cmd.AddCommand(newRoleCmd())
	cmd.AddCommand(newCertCmd())
	cmd.AddCommand(newJobCmd())

	_ = localAddress
	_ = localToken
	_ = localMount
	_ = localFormat
	return cmd
}

func init() {
	rootCmd = newRootCmd()
}

func getClient() (*client.Client, error) {
	return client.NewClient(client.Config{
		Address: flagAddress,
		Token:   flagToken,
		Mount:   flagMount,
	})
}

func printOutput(data any) {
	if flagFormat == "json" {
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

// ---- Accounts ----

func newAccountCmd() *cobra.Command {
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
			cli, err := getClient()
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
			if flagFormat == "json" {
				printOutput(acc)
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
			cli, err := getClient()
			if err != nil {
				return err
			}
			acc, err := cli.GetAccount(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			printOutput(acc)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出全部已注册的 ACME 账户",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			list, err := cli.ListAccounts(cmd.Context())
			if err != nil {
				return err
			}
			if flagFormat == "json" {
				printOutput(list)
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
			cli, err := getClient()
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

	cmd.AddCommand(regCmd, getCmd, listCmd, deactCmd)
	return cmd
}

// ---- DNS Providers ----

func newProviderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provider",
		Short: "DNS-01 Provider 凭据与配置管理",
	}

	var (
		pType             string
		credMount         string
		credPath          string
		propTimeout       string
		pollInterval      string
		skipPropagation   bool
		propWait          int
		pResolvers        []string
	)

	setCmd := &cobra.Command{
		Use:   "set <name>",
		Short: "配置或更新 DNS Provider (支持单独字段增量覆盖)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cli, err := getClient()
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
			if cmd.Flags().Changed("cred-path") || cmd.Flags().Changed("cred-mount") {
				mount := credMount
				if mount == "" {
					mount = "secret"
				}
				if p.CredentialsRef != nil && !cmd.Flags().Changed("cred-mount") {
					mount = p.CredentialsRef.Mount
				}
				p.CredentialsRef = &api.CredentialsRef{
					Mount: mount,
					Path:  credPath,
				}
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
			if p.CredentialsRef == nil || p.CredentialsRef.Path == "" {
				return fmt.Errorf("全新配置 DNS Provider 时 --cred-path 为必填项")
			}

			if err := cli.SetDNSProvider(cmd.Context(), name, p); err != nil {
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
			cli, err := getClient()
			if err != nil {
				return err
			}
			p, err := cli.GetDNSProvider(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			printOutput(p)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出全部 DNS Provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			list, err := cli.ListDNSProviders(cmd.Context())
			if err != nil {
				return err
			}
			if flagFormat == "json" {
				printOutput(list)
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
			cli, err := getClient()
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

	cmd.AddCommand(setCmd, getCmd, listCmd, delCmd)
	return cmd
}

// ---- Roles ----

func newRoleCmd() *cobra.Command {
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
			cli, err := getClient()
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
			cli, err := getClient()
			if err != nil {
				return err
			}
			r, err := cli.GetRole(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			printOutput(r)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出全部 Role",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			list, err := cli.ListRoles(cmd.Context())
			if err != nil {
				return err
			}
			if flagFormat == "json" {
				printOutput(list)
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
				if role.AllowAnyName {
					domainsStr = "*"
				} else if domainsStr == "" {
					domainsStr = "-"
				}
				domainsStr = truncateString(domainsStr, 30)
				kvMount := role.OutputKVMount
				if kvMount == "" {
					kvMount = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d%%\t%t\t%s\n",
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
			cli, err := getClient()
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

// ---- Certs & Issue ----

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "证书签发与管理",
	}

	var (
		domainsList     []string
		cn              string
		altNames        []string
		syncFlag        bool
		noWait          bool
		waitTimeout     string
		outCert         string
		outKey          string
		skipPropagation bool
		propWait        int
		issueResolvers  []string
	)

	issueCmd := &cobra.Command{
		Use:   "issue <role>",
		Short: "通过 Role 签发证书 (默认异步并自动轮询等待完成)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := args[0]
			cli, err := getClient()
			if err != nil {
				return err
			}

			// 支持类似 acme.sh 的 -d / --domain 参数：第一个作为 CN，后续作为 altNames
			effectiveCN := cn
			effectiveAlt := altNames
			if len(domainsList) > 0 {
				if effectiveCN == "" {
					effectiveCN = domainsList[0]
				}
				if len(domainsList) > 1 {
					effectiveAlt = append(effectiveAlt, domainsList[1:]...)
				}
			}

			if effectiveCN == "" {
				return fmt.Errorf("必须指定证书主域名：使用 -d <domain> 或 --cn <domain>")
			}

			// 发起签发请求
			issueOpts := api.IssueOptions{
				CommonName: effectiveCN,
				AltNames:   effectiveAlt,
				Sync:       syncFlag,
				Resolvers:  issueResolvers,
			}
			if cmd.Flags().Changed("skip-check") {
				issueOpts.SkipPropagationCheck = &skipPropagation
			}
			if cmd.Flags().Changed("prop-wait") {
				issueOpts.PropagationWait = &propWait
			}

			resp, err := cli.IssueCert(cmd.Context(), role, issueOpts)
			if err != nil {
				return fmt.Errorf("发起签发失败: %w", err)
			}

			// 若直接返回证书（覆盖复用或 sync=true 路径）
			if resp.CertificatePEM != "" {
				if resp.Reused {
					fmt.Fprintf(os.Stderr, "命中已有证书覆盖复用 (reused: true)\n")
				}
				return saveOrPrintCert(resp.CertificatePEM, resp.PrivateKeyPEM, outCert, outKey, resp)
			}

			// 异步模式拿到 job_id
			jobID := resp.JobID
			fmt.Fprintf(os.Stderr, "异步签发任务已创建: %s (CommonName: %s)\n", jobID, resp.CommonName)
			if noWait {
				printOutput(resp)
				return nil
			}

			// 自动轮询等待
			timeout := 3 * time.Minute
			if waitTimeout != "" {
				d, err := time.ParseDuration(waitTimeout)
				if err != nil {
					return fmt.Errorf("非法 wait-timeout: %w", err)
				}
				timeout = d
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			fmt.Fprintf(os.Stderr, "正在轮询等待签发完成 (超时 %s)...\n", timeout)
			detail, err := cli.PollJobUntilDone(ctx, jobID, 2*time.Second, func(j *api.JobDetail) {
				fmt.Fprintf(os.Stderr, "  任务状态: %s (更新时间: %s)\n", j.Status, j.UpdatedAt)
			})
			if err != nil {
				return fmt.Errorf("等待任务完成失败: %w", err)
			}

			if detail.Cert != nil {
				return saveOrPrintCert(detail.Cert.CertificatePEM, detail.Cert.PrivateKeyPEM, outCert, outKey, detail)
			}
			printOutput(detail)
			return nil
		},
	}
	issueCmd.Flags().StringSliceVarP(&domainsList, "domain", "d", nil, "域名列表 (类似 acme.sh，可重复指定或逗号分隔，首个为主域名 CN)")
	issueCmd.Flags().StringVar(&cn, "cn", "", "证书 Common Name (可选，若指定 -d 则以 -d 首个域名为准)")
	issueCmd.Flags().StringSliceVar(&altNames, "alt", nil, "证书 SAN 备用域名列表")
	issueCmd.Flags().BoolVar(&syncFlag, "sync", false, "强制使用同步阻塞签发 (不推荐)")
	issueCmd.Flags().BoolVar(&noWait, "no-wait", false, "仅提交异步任务，不自动在终端等待结果")
	issueCmd.Flags().StringVar(&waitTimeout, "wait-timeout", "3m", "等待完成的超时时间")
	issueCmd.Flags().StringVar(&outCert, "out-cert", "", "将证书保存到本地文件路径")
	issueCmd.Flags().StringVar(&outKey, "out-key", "", "将私钥保存到本地文件路径")
	issueCmd.Flags().BoolVar(&skipPropagation, "skip-check", false, "单次签发覆盖：跳过 lego 本地预检")
	issueCmd.Flags().IntVar(&propWait, "prop-wait", 0, "单次签发覆盖：固定等待秒数")
	issueCmd.Flags().StringSliceVar(&issueResolvers, "resolvers", nil, "单次签发覆盖：指定递归 DNS 解析器 (例如 223.5.5.5:53,1.1.1.1:53)")

	// ---- 1. cert list ----
	var listRole string
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出已签发/已缓存的证书",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			certs, err := cli.ListCerts(cmd.Context(), listRole)
			if err != nil {
				return err
			}
			if flagFormat == "json" {
				printOutput(certs)
				return nil
			}
			if len(certs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "未找到任何证书。")
				return nil
			}

			tw := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(tw, "COMMON NAME\tROLE\tACCOUNT\tEXPIRES\tSTATUS")
			for _, c := range certs {
				rem := formatRemaining(c.NotAfter)
				status := "Active"
				if rem == "Expired" {
					status = "Expired"
				} else if strings.HasSuffix(rem, "d") {
					// 大于 30 天 Active，否则 Expiring
					var days int
					_, _ = fmt.Sscanf(rem, "%dd", &days)
					if days <= 30 {
						status = "Expiring"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					c.CommonName, c.Role, c.Account, rem, status)
			}
			_ = tw.Flush()
			return nil
		},
	}
	listCmd.Flags().StringVar(&listRole, "role", "", "过滤指定 Role 的证书 (默认展示全部)")

	// ---- 2. cert get ----
	var getOutCert, getOutKey string
	getCmd := &cobra.Command{
		Use:   "get <role> <cn>",
		Short: "获取指定证书详情与公私钥",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := args[0]
			cn := args[1]
			cli, err := getClient()
			if err != nil {
				return err
			}
			detail, err := cli.GetCert(cmd.Context(), role, cn)
			if err != nil {
				return err
			}
			if getOutCert != "" || getOutKey != "" {
				return saveOrPrintCert(detail.CertificatePEM, detail.PrivateKeyPEM, getOutCert, getOutKey, detail)
			}
			if flagFormat == "json" {
				printOutput(detail)
				return nil
			}
			fmt.Printf("Common Name:    %s\n", detail.CommonName)
			fmt.Printf("Domains:        %s\n", strings.Join(detail.Domains, ", "))
			fmt.Printf("Role:           %s\n", detail.Role)
			fmt.Printf("Account:        %s\n", detail.Account)
			fmt.Printf("Not Before:     %s\n", detail.NotBefore)
			fmt.Printf("Not After:      %s\n", detail.NotAfter)
			fmt.Printf("Needs Renewal:  %v\n", detail.NeedsRenewal)
			fmt.Printf("\n--- CERTIFICATE ---\n%s", detail.CertificatePEM)
			return nil
		},
	}
	getCmd.Flags().StringVar(&getOutCert, "out-cert", "", "将证书保存到本地文件路径")
	getCmd.Flags().StringVar(&getOutKey, "out-key", "", "将私钥保存到本地文件路径")

	// ---- 3. cert revoke ----
	revokeCmd := &cobra.Command{
		Use:   "revoke <role> <cn>",
		Short: "撤销指定证书并从集群中清理",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := args[0]
			cn := args[1]
			cli, err := getClient()
			if err != nil {
				return err
			}
			if err := cli.RevokeCert(cmd.Context(), role, cn); err != nil {
				return fmt.Errorf("撤销证书失败: %w", err)
			}
			fmt.Printf("证书 %s/%s 已撤销并从存储缓存中清除。\n", role, cn)
			return nil
		},
	}

	// ---- 4. cert renew ----
	var renewSync bool
	renewCmd := &cobra.Command{
		Use:   "renew <role> <cn>",
		Short: "主动触发已有证书的续签",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := args[0]
			cn := args[1]
			cli, err := getClient()
			if err != nil {
				return err
			}
			resp, err := cli.RenewCert(cmd.Context(), role, cn, renewSync)
			if err != nil {
				return fmt.Errorf("触发续签失败: %w", err)
			}
			if resp.CertificatePEM != "" {
				fmt.Println("同步续签成功：")
				fmt.Println(resp.CertificatePEM)
				return nil
			}
			fmt.Printf("续签异步任务已提交: %s (轮询路径: %s)\n", resp.JobID, resp.PollPath)
			return nil
		},
	}
	renewCmd.Flags().BoolVar(&renewSync, "sync", false, "强制使用同步阻塞续签")

	cmd.AddCommand(issueCmd, listCmd, getCmd, revokeCmd, renewCmd)
	return cmd
}

func saveOrPrintCert(certPEM, keyPEM, outCert, outKey string, fullObj any) error {
	if outCert != "" && certPEM != "" {
		if err := os.WriteFile(outCert, []byte(certPEM), 0o644); err != nil {
			return fmt.Errorf("写入证书文件失败: %w", err)
		}
		fmt.Fprintf(os.Stderr, "证书已保存到: %s\n", outCert)
	}
	if outKey != "" && keyPEM != "" {
		if err := os.WriteFile(outKey, []byte(keyPEM), 0o600); err != nil {
			return fmt.Errorf("写入私钥文件失败: %w", err)
		}
		fmt.Fprintf(os.Stderr, "私钥已保存到: %s\n", outKey)
	}

	if outCert == "" && outKey == "" {
		if flagFormat == "json" {
			printOutput(fullObj)
		} else {
			fmt.Println(certPEM)
			if keyPEM != "" {
				fmt.Println(keyPEM)
			}
		}
	}
	return nil
}

// ---- Jobs ----

func newJobCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "job",
		Short: "异步签发 Job 状态查询与管理",
	}

	getCmd := &cobra.Command{
		Use:   "get <job_id>",
		Short: "获取 Job 详细信息与结果",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			job, err := cli.GetJob(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			printOutput(job)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出全部 Job",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			list, err := cli.ListJobs(cmd.Context())
			if err != nil {
				return err
			}
			if flagFormat == "json" {
				printOutput(list)
				return nil
			}
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "未找到任何 Job。")
				return nil
			}

			// 获取每个 job 的详情并按 tabular 格式美化输出
			tw := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(tw, "JOB ID\tROLE\tSTATUS\tCOMMON NAME\tAGE\tERROR")
			for _, id := range list {
				j, err := cli.GetJob(cmd.Context(), id)
				if err != nil {
					fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t%s\n", id, "读取失败")
					continue
				}
				ts := j.UpdatedAt
				if ts == "" {
					ts = j.CreatedAt
				}
				errSummary := truncateString(j.Error, 35)
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					j.ID, j.Role, j.Status, j.CommonName, formatAge(ts), errSummary)
			}
			_ = tw.Flush()
			return nil
		},
	}

	var (
		pruneFailedOnly bool
		pruneOlderThan  string
		pruneYes        bool
	)
	pruneCmd := &cobra.Command{
		Use:   "prune",
		Short: "自动清理处于终态 (completed / failed) 的历史 Job",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}

			var olderDur time.Duration
			if pruneOlderThan != "" {
				d, err := time.ParseDuration(pruneOlderThan)
				if err != nil {
					return fmt.Errorf("非法 older-than 时长: %w", err)
				}
				olderDur = d
			}

			if !pruneYes {
				targetDesc := "所有已完成或已失败的 Job"
				if pruneFailedOnly {
					targetDesc = "所有已失败的 Job"
				}
				if olderDur > 0 {
					targetDesc += fmt.Sprintf(" (存在时间超过 %s)", olderDur)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "确定要清理 %s 吗？[y/N]: ", targetDesc)
				var ans string
				_, _ = fmt.Scanln(&ans)
				if strings.ToLower(strings.TrimSpace(ans)) != "y" {
					fmt.Fprintln(cmd.OutOrStdout(), "操作已取消。")
					return nil
				}
			}

			pruned, err := cli.PruneJobs(cmd.Context(), api.PruneJobOptions{
				FailedOnly: pruneFailedOnly,
				OlderThan:  olderDur,
			})
			if err != nil {
				return err
			}

			if flagFormat == "json" {
				printOutput(pruned)
				return nil
			}

			if len(pruned) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "未发现需要清理的终态 Job。")
				return nil
			}

			tw := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintf(tw, "已清理 %d 个 Job:\n", len(pruned))
			fmt.Fprintln(tw, "JOB ID\tROLE\tSTATUS\tCOMMON NAME\tAGE")
			for _, p := range pruned {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					p.ID, p.Role, p.Status, p.CN, formatAge(p.UpdatedAt))
			}
			_ = tw.Flush()
			return nil
		},
	}
	pruneCmd.Flags().BoolVar(&pruneFailedOnly, "failed-only", false, "仅清理失败的 Job，保留成功历史")
	pruneCmd.Flags().StringVar(&pruneOlderThan, "older-than", "", "仅清理距今超过指定时长的 Job (例如 24h, 7d)")
	pruneCmd.Flags().BoolVarP(&pruneYes, "yes", "y", false, "无需确认直接清理")

	var waitTimeout string
	waitCmd := &cobra.Command{
		Use:   "wait <job_id>",
		Short: "等待指定 Job 变为 completed 或 failed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			timeout := 3 * time.Minute
			if waitTimeout != "" {
				d, err := time.ParseDuration(waitTimeout)
				if err != nil {
					return fmt.Errorf("非法 wait-timeout: %w", err)
				}
				timeout = d
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			job, err := cli.PollJobUntilDone(ctx, args[0], 2*time.Second, func(j *api.JobDetail) {
				fmt.Fprintf(os.Stderr, "状态: %s (更新: %s)\n", j.Status, j.UpdatedAt)
			})
			if err != nil {
				return err
			}
			printOutput(job)
			return nil
		},
	}
	waitCmd.Flags().StringVar(&waitTimeout, "timeout", "3m", "等待超时")

	delCmd := &cobra.Command{
		Use:   "delete <job_id>",
		Short: "删除已终态 (completed 或 failed) 的 Job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			if err := cli.DeleteJob(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Printf("Job %q 已删除\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(getCmd, listCmd, waitCmd, delCmd, pruneCmd)
	return cmd
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
