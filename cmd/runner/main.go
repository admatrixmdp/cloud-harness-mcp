// Command runner is the trusted workspace lifecycle service (today apps/runner).
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/runner"
)

var listen string

func main() {
	cmd := &cobra.Command{
		Use:   "runner",
		Short: "Cloud Harness runner (Go port)",
		Long: `Owns Docker authority, SQLite state, GitHub App brokering, and cleanup.

This process is the only Compose service that may mount the Docker socket.
This slice serves /healthz and /v1/operations (operations still return UNAVAILABLE).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			h := runner.Handler(runner.Options{ServiceToken: os.Getenv("RUNNER_SERVICE_TOKEN")})
			slog.Info("runner listening", "addr", listen)
			return http.ListenAndServe(listen, h)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:3001", "HTTP listen address (loopback by default)")
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
