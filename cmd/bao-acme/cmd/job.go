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

func NewJobCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "job",
		Short: "异步签发 Job 状态查询与管理",
	}

	getCmd := &cobra.Command{
		Use:   "get <job_id>",
		Short: "获取 Job 详细信息与结果",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			job, err := cli.GetJob(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			PrintOutput(job)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "列出全部 Job",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
			if err != nil {
				return err
			}
			list, err := cli.ListJobs(cmd.Context())
			if err != nil {
				return err
			}
			if FlagFormat == "json" {
				PrintOutput(list)
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
			cli, err := GetClient()
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

			if FlagFormat == "json" {
				PrintOutput(pruned)
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
			cli, err := GetClient()
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
			PrintOutput(job)
			return nil
		},
	}
	waitCmd.Flags().StringVar(&waitTimeout, "timeout", "3m", "等待超时")

	delCmd := &cobra.Command{
		Use:   "delete <job_id>",
		Short: "删除已终态 (completed 或 failed) 的 Job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := GetClient()
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
