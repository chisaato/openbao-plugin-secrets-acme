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

func init() {
	rootCmd.PersistentFlags().StringVar(&flagAddress, "address", "", "OpenBao 服务地址 (默认从 BAO_ADDR/VAULT_ADDR 读取，或 http://127.0.0.1:8200)")
	rootCmd.PersistentFlags().StringVar(&flagToken, "token", "", "OpenBao 访问 Token (默认从 BAO_TOKEN/VAULT_TOKEN 读取)")
	rootCmd.PersistentFlags().StringVar(&flagMount, "mount", "acme", "ACME 插件挂载路径")
	rootCmd.PersistentFlags().StringVarP(&flagFormat, "format", "f", "text", "输出格式 (text 或 json)")

	rootCmd.AddCommand(newAccountCmd())
	rootCmd.AddCommand(newProviderCmd())
	rootCmd.AddCommand(newRoleCmd())
	rootCmd.AddCommand(newCertCmd())
	rootCmd.AddCommand(newJobCmd())
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
		Short: "列出全部账户",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			list, err := cli.ListAccounts(cmd.Context())
			if err != nil {
				return err
			}
			printOutput(list)
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
	)

	setCmd := &cobra.Command{
		Use:   "set <name>",
		Short: "配置或更新 DNS Provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cli, err := getClient()
			if err != nil {
				return err
			}

			p := api.DNSProvider{
				Type:                 pType,
				SkipPropagationCheck: skipPropagation,
				PropagationWait:      propWait,
			}
			if credMount != "" && credPath != "" {
				p.CredentialsRef = &api.CredentialsRef{
					Mount: credMount,
					Path:  credPath,
				}
			}
			if propTimeout != "" {
				d, err := time.ParseDuration(propTimeout)
				if err != nil {
					return fmt.Errorf("非法 propagation-timeout: %w", err)
				}
				p.PropagationTimeout = d
			}
			if pollInterval != "" {
				d, err := time.ParseDuration(pollInterval)
				if err != nil {
					return fmt.Errorf("非法 polling-interval: %w", err)
				}
				p.PollingInterval = d
			}

			if err := cli.SetDNSProvider(cmd.Context(), name, p); err != nil {
				return err
			}
			fmt.Printf("DNS Provider %q 配置成功\n", name)
			return nil
		},
	}
	setCmd.Flags().StringVar(&pType, "type", "", "Provider 类型 (如 alidns, tencentcloud，必填)")
	setCmd.Flags().StringVar(&credMount, "cred-mount", "secret", "凭据所在的 KV mount")
	setCmd.Flags().StringVar(&credPath, "cred-path", "", "凭据所在的 KV 相对路径 (必填)")
	setCmd.Flags().StringVar(&propTimeout, "prop-timeout", "2m", "DNS 传播超时")
	setCmd.Flags().StringVar(&pollInterval, "poll-interval", "2s", "DNS 轮询间隔")
	setCmd.Flags().BoolVar(&skipPropagation, "skip-check", false, "跳过预检 (适用于本地 pebble 或自建权威 DNS)")
	setCmd.Flags().IntVar(&propWait, "prop-wait", 0, "跳过预检时的固定等待秒数")
	_ = setCmd.MarkFlagRequired("type")
	_ = setCmd.MarkFlagRequired("cred-path")

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
			printOutput(list)
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
		Short: "创建或更新 Role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cli, err := getClient()
			if err != nil {
				return err
			}
			r := api.Role{
				Account:          account,
				AllowedDomains:   allowedDomains,
				AllowBareDomains: allowBare,
				AllowSubdomains:  allowSub,
				AllowAnyName:     allowAny,
				DisableCache:     disableCache,
				DisableCertReuse: disableCertReuse,
				CacheForRatio:    cacheForRatio,
				OutputKVMount:    outputKVMount,
			}
			if err := cli.SetRole(cmd.Context(), name, r); err != nil {
				return err
			}
			fmt.Printf("Role %q 配置成功\n", name)
			return nil
		},
	}
	setCmd.Flags().StringVar(&account, "account", "", "关联的 ACME 账户名 (必填)")
	setCmd.Flags().StringSliceVar(&allowedDomains, "allowed-domains", nil, "白名单根域名 (逗号分隔)")
	setCmd.Flags().BoolVar(&allowBare, "allow-bare", true, "允许白名单裸域")
	setCmd.Flags().BoolVar(&allowSub, "allow-sub", true, "允许白名单子域")
	setCmd.Flags().BoolVar(&allowAny, "allow-any", false, "允许任意域名 (跳过白名单检查)")
	setCmd.Flags().BoolVar(&disableCache, "disable-cache", false, "禁用证书缓存")
	setCmd.Flags().BoolVar(&disableCertReuse, "disable-reuse", false, "禁用同账户泛域名覆盖复用")
	setCmd.Flags().IntVar(&cacheForRatio, "cache-ratio", 80, "缓存有效期百分比")
	setCmd.Flags().StringVar(&outputKVMount, "output-kv", "", "输出证书与私钥的 KV-v2 挂载路径 (可选)")
	_ = setCmd.MarkFlagRequired("account")

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
			printOutput(list)
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
		cn         string
		altNames   []string
		syncFlag   bool
		noWait     bool
		waitTimeout string
		outCert    string
		outKey     string
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

			// 发起签发请求
			resp, err := cli.IssueCert(cmd.Context(), role, api.IssueOptions{
				CommonName: cn,
				AltNames:   altNames,
				Sync:       syncFlag,
			})
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
	issueCmd.Flags().StringVar(&cn, "cn", "", "证书 Common Name (必填)")
	issueCmd.Flags().StringSliceVar(&altNames, "alt", nil, "证书 SAN 备用域名列表")
	issueCmd.Flags().BoolVar(&syncFlag, "sync", false, "强制使用同步阻塞签发 (不推荐)")
	issueCmd.Flags().BoolVar(&noWait, "no-wait", false, "仅提交异步任务，不自动在终端等待结果")
	issueCmd.Flags().StringVar(&waitTimeout, "wait-timeout", "3m", "等待完成的超时时间")
	issueCmd.Flags().StringVar(&outCert, "out-cert", "", "将证书保存到本地文件路径")
	issueCmd.Flags().StringVar(&outKey, "out-key", "", "将私钥保存到本地文件路径")
	_ = issueCmd.MarkFlagRequired("cn")

	cmd.AddCommand(issueCmd)
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
		Short: "列出全部 Job ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := getClient()
			if err != nil {
				return err
			}
			list, err := cli.ListJobs(cmd.Context())
			if err != nil {
				return err
			}
			printOutput(list)
			return nil
		},
	}

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

	cmd.AddCommand(getCmd, listCmd, waitCmd, delCmd)
	return cmd
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
