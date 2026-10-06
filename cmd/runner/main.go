// Command runner is the trusted workspace lifecycle service (today apps/runner).
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/healthcheck"
	"github.com/bestagentkits/cloud-harness-mcp/internal/runner"
)

var (
	listen         string
	healthcheckURL string
)

func main() {
	cmd := &cobra.Command{
		Use:   "runner",
		Short: "Cloud Harness runner (Go port)",
		Long: `Owns Docker authority, SQLite state, GitHub App brokering, and cleanup.

This process is the only Compose service that may mount the Docker socket.
Workspace lifecycle stays fail-closed. workspace_open clones through a helper
container (token on stdin only) then creates the executor with the job repo
mounted at /workspace. skills_run after an owner grant launches a disposable
UID 10001 helper; it never falls back to a local child process.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			healthcheck.MaybeExit(healthcheckURL, listen, "/healthz")
			svc, err := runner.ProductionService(os.Getenv)
			if err != nil {
				return err
			}
			h := runner.Handler(runner.Options{
				ServiceToken: runner.ServiceTokenFromEnv(os.Getenv),
				Service:      svc,
			})
			slog.Info("runner listening", "addr", listen)
			return http.ListenAndServe(listen, h)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:3001", "HTTP listen address (loopback by default)")
	cmd.Flags().StringVar(&healthcheckURL, "healthcheck", "", "GET this URL and exit (Compose probe)")
	cmd.Flags().Lookup("healthcheck").NoOptDefVal = "auto"
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
