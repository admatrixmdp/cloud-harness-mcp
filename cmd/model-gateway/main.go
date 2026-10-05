// Command model-gateway is the trusted model API proxy for subagents
// (today apps/model-gateway).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "model-gateway",
		Short: "Cloud Harness model gateway (Go port scaffold)",
		Long: `Routes subagent model calls through opaque short-lived capability leases.
Executors never receive provider credentials.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "scaffold: model-gateway not yet implemented")
		},
	}
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
