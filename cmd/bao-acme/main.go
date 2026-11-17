package main

import (
	"fmt"
	"os"

	"github.com/chisaato/openbao-plugin-secrets-acme/cmd/bao-acme/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		// cobra 已将原错误打印到 stderr；403 时在其后附上分类指引，不改退出码与错误文本。
		if hint, ok := cmd.ForbiddenHint(err); ok {
			fmt.Fprintln(os.Stderr, hint)
		}
		os.Exit(1)
	}
}
