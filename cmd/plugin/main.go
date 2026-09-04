package main

import (
	"fmt"
	"os"

	"github.com/chisaato/openbao-plugin-secrets-acme/acme"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

// 版本自报经 acme.Version（由 justfile ldflags 注入，v 前缀 SemVer），
// 由 Factory 设置 framework.Backend.RunningVersion。
func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "parse flags: %v\n", err)
		os.Exit(1)
	}
	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: acme.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "plugin server exited: %v\n", err)
		os.Exit(1)
	}
}
