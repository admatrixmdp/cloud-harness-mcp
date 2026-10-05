// Command runner is the trusted workspace lifecycle service (today apps/runner).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "runner",
		Short: "Cloud Harness runner (Go port scaffold)",
		Long: `Owns Docker authority, SQLite state, GitHub App brokering, and cleanup.

This process is the only Compose service that may mount the Docker socket.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "scaffold: runner HTTP RPC not yet implemented")
		},
	}
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
