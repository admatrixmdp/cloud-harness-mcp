// Command provisioning-proxy is the dual-homed helper egress proxy
// (today deploy/provisioning-proxy.mjs).
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/healthcheck"
	"github.com/bestagentkits/cloud-harness-mcp/internal/provisioning"
)

func main() {
	var healthcheckURL string
	cmd := &cobra.Command{
		Use:   "provisioning-proxy",
		Short: "Allowlisted helper egress proxy",
		Long: `Dual-homed CONNECT/HTTP proxy for toolkit and clone helpers.

Must not publish a host port, receive secrets, or join the API/runner control
network. Destinations are allowlisted and fail closed on private, loopback,
link-local, and cloud-metadata addresses. CONNECT is port 443 only.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := provisioning.FromEnv()
			if err != nil {
				return err
			}
			healthcheck.MaybeExit(healthcheckURL, net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.ListenPort)), "/healthz")
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return provisioning.ListenAndServe(ctx, cfg)
		},
	}
	cmd.Flags().StringVar(&healthcheckURL, "healthcheck", "", "GET this URL and exit (Compose probe)")
	cmd.Flags().Lookup("healthcheck").NoOptDefVal = "auto"
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
