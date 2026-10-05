// Command runner is the trusted workspace lifecycle service (today apps/runner).
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/runner"
	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var listen string

func main() {
	cmd := &cobra.Command{
		Use:   "runner",
		Short: "Cloud Harness runner (Go port)",
		Long: `Owns Docker authority, SQLite state, GitHub App brokering, and cleanup.

This process is the only Compose service that may mount the Docker socket.
This slice implements workspace_open/list/status/close/capabilities in-process
(with a noop engine until Docker is wired) and fail-closed network policy.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := protocol.NetworkProfile(os.Getenv("WORKSPACE_NETWORK_PROFILE"))
			if profile == "" {
				profile = sandbox.DefaultNetworkProfile
			}
			hosts := []string{"github.com"}
			if raw := os.Getenv("ALLOWED_GIT_HOSTS"); raw != "" {
				hosts = strings.Split(raw, ",")
			}
			svc := runner.NewService(runner.Config{
				AllowedGitHosts: hosts,
				NetworkProfile:  profile,
			}, nil, nil)
			h := runner.Handler(runner.Options{ServiceToken: os.Getenv("RUNNER_SERVICE_TOKEN"), Service: svc})
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
