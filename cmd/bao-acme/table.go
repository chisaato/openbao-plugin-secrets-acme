package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// newTabWriter 创建一个配置对齐良好的标准 tabwriter.Writer
func newTabWriter(w io.Writer) *tabwriter.Writer {
	if w == nil {
		w = os.Stdout
	}
	// minwidth=0, tabwidth=8, padding=2, padchar=' ', flags=0
	return tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
}

// formatAge 计算给定的时间字符串相对于当前时间的时长（例如 3m, 2h, 5d）
func formatAge(ts string) string {
	if ts == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "-"
	}
	d := time.Since(t)
	if d < 0 {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	days := int(d.Hours() / 24)
	return fmt.Sprintf("%dd", days)
}

// formatRemaining 计算当前时间距离目标到期时间的剩余时长（例如 89d, 2h）
func formatRemaining(ts string) string {
	if ts == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "-"
	}
	d := time.Until(t)
	if d <= 0 {
		return "Expired"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	days := int(d.Hours() / 24)
	return fmt.Sprintf("%dd", days)
}

// truncateString 限制字符串最大长度，超长时以省略号结尾
func truncateString(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if maxLen <= 3 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
