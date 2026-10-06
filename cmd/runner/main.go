// Command runner is the trusted workspace lifecycle service (today apps/runner).
package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/healthcheck"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcpgw"
	"github.com/bestagentkits/cloud-harness-mcp/internal/runner"
	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
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
Workspace lifecycle stays fail-closed. skills_run after an owner grant launches a
disposable UID 10001 helper; it never falls back to a local child process.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			healthcheck.MaybeExit(healthcheckURL, listen, "/healthz")
			profile := protocol.NetworkProfile(os.Getenv("WORKSPACE_NETWORK_PROFILE"))
			if profile == "" {
				profile = sandbox.DefaultNetworkProfile
			}
			hosts := []string{"github.com"}
			if raw := os.Getenv("ALLOWED_GIT_HOSTS"); raw != "" {
				hosts = strings.Split(raw, ",")
			}
			image := os.Getenv("EXECUTOR_IMAGE")
			jobsRoot := os.Getenv("JOBS_ROOT")
			docker := &sandbox.Engine{Image: image, InstanceID: os.Getenv("INSTANCE_ID")}
			svc := runner.NewService(runner.Config{
				AllowedGitHosts: hosts,
				NetworkProfile:  profile,
				ExecutorImage:   image,
				JobsRoot:        jobsRoot,
				InstanceID:      os.Getenv("INSTANCE_ID"),
			}, nil, nil).WithDocker(docker)
			if stateDB := os.Getenv("STATE_DB"); stateDB != "" {
				if err := os.MkdirAll(filepath.Dir(stateDB), 0o700); err != nil {
					return err
				}
				db, err := sql.Open("sqlite", stateDB)
				if err != nil {
					return err
				}
				if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
					return err
				}
				gw, err := mcpgw.Open(db)
				if err != nil {
					return err
				}
				svc = svc.WithMCPGateway(gw)
			}
			h := runner.Handler(runner.Options{ServiceToken: os.Getenv("RUNNER_SERVICE_TOKEN"), Service: svc})
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
