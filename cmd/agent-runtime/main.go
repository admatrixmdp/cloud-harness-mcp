// Command agent-runtime is the in-container JSONL subagent
// (today apps/agent-runtime). Prompt and lease travel only on stdin.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"time"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/agent"
	"github.com/bestagentkits/cloud-harness-mcp/internal/healthcheck"
)

func main() {
	var hold bool
	var probeAddr string
	cmd := &cobra.Command{
		Use:   "agent-runtime",
		Short: "Cloud Harness subagent JSONL runtime (Go port)",
		Long: `Reads start/message/cancel JSONL on stdin and writes event/usage/terminal
on stdout. The opaque gateway lease rides Authorization only. Provider
credentials never enter this process. Distroless images have no sleep(1);
--hold keeps the production keepalive container alive until SIGINT/SIGTERM.
--probe HOST:PORT dials TCP and exits 0/1 so isolation tests need no node.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if probeAddr != "" {
				os.Exit(healthcheck.TCPProbe(probeAddr, time.Second))
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if hold {
				<-ctx.Done()
				return nil
			}
			return agent.ServeRuntime(ctx, os.Stdin, os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&hold, "hold", false, "block until SIGINT/SIGTERM (image keepalive; no JSONL)")
	cmd.Flags().StringVar(&probeAddr, "probe", "", "dial HOST:PORT over TCP and exit 0/1 (isolation tests; no node)")
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
