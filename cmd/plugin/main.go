package main

import (
	"fmt"
	"os"

	"github.com/chisaato/openbao-plugin-secrets-acme/acme"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

// pluginVersion 由 Makefile ldflags 注入；conf.RunningVersion 优先。
var pluginVersion = "dev"

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
