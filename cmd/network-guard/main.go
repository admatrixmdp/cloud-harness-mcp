// Command network-guard dumps iptables-save for dependency-access attestation
// (today docker/network-guard.Dockerfile ENTRYPOINT /sbin/iptables-save).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/netguard"
)

func main() {
	cmd := &cobra.Command{
		Use:   "network-guard",
		Short: "Dump host iptables-save for dependency-access attestation",
		Long: `NET_ADMIN-only probe. Prints iptables-save on stdout and exits.

Must not publish a host port, receive secrets, or mount docker.sock.
Overlay-only: compose.yaml still ships docker/network-guard.Dockerfile.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return netguard.Dump(os.Stdout, netguard.Options{})
		},
	}
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
