// Command cloud-harness-mcp is the northbound MCP process (today apps/api).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/config"
)

var (
	transport  string
	workspace  string
	gitNetwork bool
	gitPush    bool
	showVersion bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "cloud-harness-mcp",
	Short: "Cloud Harness MCP API (Go port scaffold)",
	Long: `Northbound Streamable HTTP / stdio MCP server.

This binary must not hold a Docker socket or host job mounts.
Runner RPC is the only path to workspace execution.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Println("cloud-harness-mcp (go-port scaffold)")
			return nil
		}
		opts := config.Options{
			Transport:  config.Transport(transport),
			Workspace:  workspace,
			GitNetwork: gitNetwork || gitPush,
			GitPush:    gitPush,
		}
		if err := opts.Valid(); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "scaffold: transport=%s workspace=%s\n", opts.Transport, opts.Workspace)
		return nil
	},
}

func init() {
	rootCmd.Flags().StringVar(&transport, "transport", "http", "http or stdio")
	rootCmd.Flags().StringVar(&workspace, "workspace", "", "absolute local project path (required for stdio)")
	rootCmd.Flags().BoolVar(&gitNetwork, "git-network", false, "enable local git fetch/pull")
	rootCmd.Flags().BoolVar(&gitPush, "git-push", false, "enable local git push (implies --git-network)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "print version")
}
