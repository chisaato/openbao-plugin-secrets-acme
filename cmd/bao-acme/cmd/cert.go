package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chisaato/openbao-plugin-secrets-acme/pkg/api"
	"github.com/spf13/cobra"
)

func NewCertCmd() *cobra.Command {
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
		forceIssue      bool
	)

	issueCmd := &cobra.Command{
		Use:   "issue <role>",
		Short: "通过 Role 签发证书 (默认异步并自动轮询等待完成)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := args[0]
			cli, err := GetClient()
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
				Force:      forceIssue,
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

			// 1. 若命中已有证书复用 (reused: true)
			if resp.Reused {
				if outCert != "" || outKey != "" {
					return saveOrPrintCert(resp.CertificatePEM, resp.PrivateKeyPEM, outCert, outKey, resp)
				}
				if FlagFormat == "json" {
					PrintOutput(resp)
					return nil
				}
				fmt.Fprintln(os.Stderr, "ℹ 检测到已有证书已覆盖请求域名（无需重新向 CA 申请）。")
				// 查出该 role 下匹配的证书
				allCerts, _ := cli.ListCerts(cmd.Context(), role)
				matched := api.FilterCertsByDomains(allCerts, append([]string{effectiveCN}, effectiveAlt...), true)
				if len(matched) == 0 {
					matched = api.FilterCertsByDomains(allCerts, append([]string{effectiveCN}, effectiveAlt...), false)
				}
				if len(matched) > 0 {
					fmt.Fprintln(os.Stderr, "\n匹配的现有证书：")
					tw := newTabWriter(cmd.OutOrStdout())
					fmt.Fprintln(tw, "CERT ID\tCOMMON NAME\tDOMAINS\tROLE\tEXPIRES\tSTATUS")
					for _, c := range matched {
						rem := formatRemaining(c.NotAfter)
						status := "Active"
						if rem == "Expired" {
							status = "Expired"
						}
						doms := truncateString(strings.Join(c.Domains, ", "), 35)
						fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
							c.GetShortID(), c.CommonName, doms, c.Role, rem, status)
					}
					_ = tw.Flush()
				}
				fmt.Fprintln(os.Stderr, "\n提示: 如需强制跳过缓存申请全新证书，请追加 --force 参数；或使用 `bao-acme cert get <cert_id>` 导出已有证书。")
				return nil
			}

			// 若直接返回证书（sync=true 且非复用）
			if resp.CertificatePEM != "" {
				if outCert != "" || outKey != "" {
					return saveOrPrintCert(resp.CertificatePEM, resp.PrivateKeyPEM, outCert, outKey, resp)
				}
				if FlagFormat == "json" {
					PrintOutput(resp)
					return nil
				}
				printIssueSuccessSummary(cmd.OutOrStdout(), resp.CommonName, resp.Domains, role, resp.CertificatePEM)
				return nil
			}

			// 异步模式拿到 job_id
			jobID := resp.JobID
			fmt.Fprintf(os.Stderr, "异步签发任务已创建: %s (CommonName: %s)\n", jobID, resp.CommonName)
			if noWait {
				PrintOutput(resp)
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

			if snap := detail.GetCertSnapshot(); snap != nil {
				if outCert != "" || outKey != "" {
					return saveOrPrintCert(snap.CertificatePEM, snap.PrivateKeyPEM, outCert, outKey, detail)
				}
				if FlagFormat == "json" {
					PrintOutput(detail)
					return nil
				}
				printIssueSuccessSummary(cmd.OutOrStdout(), detail.CommonName, detail.Domains, detail.Role, snap.CertificatePEM)
				return nil
			}
			PrintOutput(detail)
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
	issueCmd.Flags().BoolVar(&forceIssue, "force", false, "强制签发全新证书：跳过精确缓存与覆盖复用分支，直接向 CA 申请")

	// ---- 1. cert list ----
	var (
		listRole    string
		listDomains []string
	)
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出已签发/已缓存的证书 (支持按 Role 与 Domain 过滤)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			certs, err := cli.ListCerts(cmd.Context(), listRole)
			if err != nil {
				return err
			}
			if len(listDomains) > 0 {
				certs = api.FilterCertsByDomains(certs, listDomains, false)
			}
			if FlagFormat == "json" {
				PrintOutput(certs)
				return nil
			}
			if len(certs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "未找到任何证书。")
				return nil
			}

			tw := newTabWriter(cmd.OutOrStdout())
			fmt.Fprintln(tw, "CERT ID\tCOMMON NAME\tDOMAINS\tROLE\tEXPIRES\tSTATUS\tKV")
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
				doms := strings.Join(c.Domains, ", ")
				if doms == "" {
					doms = c.CommonName
				}
				doms = truncateString(doms, 35)
				// 类似 Docker 显示 12 位 short ID，不带省略号，便于终端双击复制
				certID := c.GetShortID()
				kvStatus := c.OutputKVStatus
				if kvStatus == "" {
					kvStatus = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					certID, c.CommonName, doms, c.Role, rem, status, kvStatus)
			}
			_ = tw.Flush()
			return nil
		},
	}
	listCmd.Flags().StringVar(&listRole, "role", "", "过滤指定 Role 的证书 (默认展示全部)")
	listCmd.Flags().StringSliceVarP(&listDomains, "domain", "d", nil, "按域名过滤 (支持泛域名匹配，例如 -d example.com 或 -d sub.example.com)")

	// ---- 2. cert get ----
	var getOutCert, getOutKey string
	getCmd := &cobra.Command{
		Use:   "get <cert_id | role cn>",
		Short: "获取指定证书详情与公私钥 (支持传单个 Cert ID 或传 role cn)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			var detail *api.CertDetail
			if len(args) == 1 {
				// 按 Cert ID / CacheKey 检索 (支持短 ID 前缀检索)
				d, err := cli.GetCertByID(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				detail = d
			} else {
				role := args[0]
				cn := args[1]
				d, err := cli.GetCert(cmd.Context(), role, cn)
				if err != nil {
					return err
				}
				detail = d
			}

			if getOutCert != "" || getOutKey != "" {
				return saveOrPrintCert(detail.CertificatePEM, detail.PrivateKeyPEM, getOutCert, getOutKey, detail)
			}
			if FlagFormat == "json" {
				PrintOutput(detail)
				return nil
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Cert ID:        %s\n", detail.GetID())
			fmt.Fprintf(out, "Common Name:    %s\n", detail.CommonName)
			fmt.Fprintf(out, "Domains:        %s\n", strings.Join(detail.Domains, ", "))
			fmt.Fprintf(out, "Role:           %s\n", detail.Role)
			fmt.Fprintf(out, "Account:        %s\n", detail.Account)
			fmt.Fprintf(out, "Not Before:     %s\n", detail.NotBefore)
			fmt.Fprintf(out, "Not After:      %s\n", detail.NotAfter)
			fmt.Fprintf(out, "Needs Renewal:  %v\n", detail.NeedsRenewal)
			kvStatus := detail.OutputKVStatus
			if kvStatus == "" {
				kvStatus = "-"
			}
			kvMount := detail.OutputKVMount
			if kvMount == "" {
				kvMount = "-"
			}
			fmt.Fprintf(out, "KV Mount:       %s\n", kvMount)
			fmt.Fprintf(out, "KV Status:      %s\n", kvStatus)
			if detail.OutputKVPath != "" {
				fmt.Fprintf(out, "KV Path:        %s\n", detail.OutputKVPath)
			}
			fmt.Fprintf(out, "\n--- CERTIFICATE ---\n%s", detail.CertificatePEM)
			return nil
		},
	}
	getCmd.Flags().StringVar(&getOutCert, "out-cert", "", "将证书保存到本地文件路径")
	getCmd.Flags().StringVar(&getOutKey, "out-key", "", "将私钥保存到本地文件路径")

	// ---- 3. cert revoke ----
	revokeCmd := &cobra.Command{
		Use:   "revoke <cert_id | role cn>",
		Short: "撤销指定证书并从集群中清理 (支持传单个 Cert ID 或传 role cn)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				certID := args[0]
				if err := cli.RevokeCertByID(cmd.Context(), certID); err != nil {
					return fmt.Errorf("撤销证书失败: %w", err)
				}
				fmt.Printf("证书 %s 已撤销并从存储缓存中清除。\n", certID)
				return nil
			}
			role := args[0]
			cn := args[1]
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
		Short: "触发证书重新签发与续期",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := args[0]
			cn := args[1]
			cli, err := GetClient()
			if err != nil {
				return err
			}
			resp, err := cli.RenewCert(cmd.Context(), role, cn, renewSync)
			if err != nil {
				return fmt.Errorf("续签请求失败: %w", err)
			}
			if resp.JobID != "" {
				fmt.Fprintf(os.Stderr, "续签任务已创建: %s\n", resp.JobID)
			}
			PrintOutput(resp)
			return nil
		},
	}
	renewCmd.Flags().BoolVar(&renewSync, "sync", false, "强制使用同步阻塞续签")

	cmd.AddCommand(issueCmd, listCmd, getCmd, revokeCmd, renewCmd)
	return cmd
}
