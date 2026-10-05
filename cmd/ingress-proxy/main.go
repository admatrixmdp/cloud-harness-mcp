// Command ingress-proxy is the credential-free loopback byte proxy
// (today deploy/ingress-proxy.mjs).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "ingress-proxy",
		Short: "Credential-free TCP/HTTP ingress proxy (Go port scaffold)",
		Long: `The only Compose service that may publish a host port, bound to loopback.

Must not receive secrets or join the API/runner control network.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "scaffold: ingress-proxy not yet implemented")
		},
	}
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
