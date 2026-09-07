package main

import (
	"os"

	"github.com/chisaato/openbao-plugin-secrets-acme/cmd/bao-acme/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
