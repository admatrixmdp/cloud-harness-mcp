// Command model-gateway is the trusted model API proxy for subagents
// (today apps/model-gateway). Executors never receive provider credentials.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/agent"
)

var listen string

func main() {
	cmd := &cobra.Command{
		Use:   "model-gateway",
		Short: "Cloud Harness model gateway (Go port)",
		Long: `Routes subagent model calls through opaque short-lived capability leases.
Provider credentials stay on this process. Subagent containers get only the
lease token and a per-agent internal network.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			h := agent.Handler(agent.NewRegistry(), map[string]agent.Profile{})
			slog.Info("model-gateway listening", "addr", listen)
			return http.ListenAndServe(listen, h)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:3210", "HTTP listen address (loopback by default)")
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
