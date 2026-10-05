// Command cloud-harness-mcp is the northbound MCP process (today apps/api).
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/api"
	"github.com/bestagentkits/cloud-harness-mcp/internal/config"
	"github.com/bestagentkits/cloud-harness-mcp/internal/healthcheck"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
)

var (
	transport      string
	workspace      string
	gitNetwork     bool
	gitPush        bool
	showVersion    bool
	listen         string
	healthcheckURL string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "cloud-harness-mcp",
	Short: "Cloud Harness MCP API (Go port)",
	Long: `Northbound Streamable HTTP / stdio MCP server.

This binary must not hold a Docker socket or host job mounts.
Runner RPC is the only path to workspace execution in HTTP mode.
Local stdio executes confined file/search/exec tools in --workspace.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Fprintln(cmd.OutOrStdout(), "cloud-harness-mcp (go-port)")
			return nil
		}
		healthcheck.MaybeExit(healthcheckURL, listen, "/healthz")
		opts := config.Options{
			Transport:  config.Transport(transport),
			Workspace:  workspace,
			GitNetwork: gitNetwork || gitPush,
			GitPush:    gitPush,
		}
		if err := opts.Valid(); err != nil {
			return err
		}
		if opts.Transport == config.TransportStdio {
			if !filepath.IsAbs(opts.Workspace) {
				return fmt.Errorf("--workspace path must be absolute")
			}
			info, err := os.Stat(opts.Workspace)
			if err != nil {
				return fmt.Errorf("failed to resolve workspace path %q: %w", opts.Workspace, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("--workspace path %q is not a directory", opts.Workspace)
			}
			root, err := filepath.EvalSymlinks(opts.Workspace)
			if err != nil {
				root = opts.Workspace
			}
			return mcp.ServeStdio(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), mcp.HandlerOptions{
				Local: mcp.LocalBackend{Root: root, GitNetwork: opts.GitNetwork, GitPush: opts.GitPush},
			})
		}
		var runner *mcp.RunnerClient
		if url := os.Getenv("RUNNER_URL"); url != "" {
			runner = &mcp.RunnerClient{
				BaseURL:      url,
				ServiceToken: os.Getenv("RUNNER_SERVICE_TOKEN"),
				OwnerID:      os.Getenv("OWNER_ID"),
			}
		}
		handler := api.Handler(api.Options{
			BearerToken: os.Getenv("MCP_BEARER_TOKEN"),
			Runner:      runner,
		})
		slog.Info("api listening", "addr", listen)
		return http.ListenAndServe(listen, handler)
	},
}

func init() {
	rootCmd.Flags().StringVar(&transport, "transport", "http", "http or stdio")
	rootCmd.Flags().StringVar(&workspace, "workspace", "", "absolute local project path (required for stdio)")
	rootCmd.Flags().BoolVar(&gitNetwork, "git-network", false, "enable local git fetch/pull")
	rootCmd.Flags().BoolVar(&gitPush, "git-push", false, "enable local git push (implies --git-network)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "print version")
	rootCmd.Flags().StringVar(&listen, "listen", "127.0.0.1:3000", "HTTP listen address (loopback by default)")
	rootCmd.Flags().StringVar(&healthcheckURL, "healthcheck", "", "GET this URL and exit (Compose probe)")
	rootCmd.Flags().Lookup("healthcheck").NoOptDefVal = "auto"
}
