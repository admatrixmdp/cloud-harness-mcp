// Command ingress-proxy is the credential-free loopback byte proxy
// (today deploy/ingress-proxy.mjs).
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
	"github.com/bestagentkits/cloud-harness-mcp/internal/ingress"
)

func main() {
	var healthcheckURL string
	cmd := &cobra.Command{
		Use:   "ingress-proxy",
		Short: "Credential-free TCP ingress proxy",
		Long: `The only Compose service that may publish a host port, bound to loopback.

Must not receive secrets or join the API/runner control network.
This process is a raw TCP byte pipe; it never parses HTTP or attaches credentials.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := ingress.FromEnv()
			if err != nil {
				return err
			}
			healthcheck.MaybeExit(healthcheckURL, net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.ListenPort)), "/readyz")
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return ingress.ListenAndServe(ctx, cfg)
		},
	}
	cmd.Flags().StringVar(&healthcheckURL, "healthcheck", "", "GET this URL and exit (Compose probe)")
	cmd.Flags().Lookup("healthcheck").NoOptDefVal = "auto"
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
