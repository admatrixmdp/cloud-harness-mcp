// Command model-gateway is the trusted model API proxy for subagents
// (today apps/model-gateway). Executors never receive provider credentials.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/bestagentkits/cloud-harness-mcp/internal/agent"
	"github.com/bestagentkits/cloud-harness-mcp/internal/healthcheck"
)

var (
	listen         string
	healthcheckURL string
)

func main() {
	cmd := &cobra.Command{
		Use:   "model-gateway",
		Short: "Cloud Harness model gateway (Go port)",
		Long: `Routes subagent model calls through opaque short-lived capability leases.
Provider credentials stay on this process. Subagent containers get only the
lease token and a per-agent internal network. The Unix control socket (mode
0600) mints leases for the runner; the raw token never appears in logs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			healthcheck.MaybeExit(healthcheckURL, listen, "/healthz")
			profiles := map[string]agent.Profile{}
			if url := os.Getenv("MODEL_UPSTREAM_URL"); url != "" {
				profiles["default"] = agent.Profile{
					ID:                     "default",
					Model:                  os.Getenv("MODEL_UPSTREAM_MODEL"),
					DownstreamPath:         "/v1/chat/completions",
					InputMicrosPerMillion:  0,
					OutputMicrosPerMillion: 0,
					Limits: agent.ProfileLimits{
						MaxInputTokens:  10_000_000,
						MaxOutputTokens: 2_000_000,
						MaxCostMicros:   1_000_000_000_000,
					},
					Upstream: agent.Upstream{
						URL:              url,
						Credential:       os.Getenv("MODEL_UPSTREAM_CREDENTIAL"),
						CredentialHeader: "Authorization",
						CredentialScheme: "Bearer",
						TLSCAFile:        os.Getenv("MODEL_UPSTREAM_TLS_CA_FILE"),
					},
				}
			}
			reg := agent.NewRegistry()
			live := agent.NewLiveRegistry(os.Getenv("MODEL_GATEWAY_MODE") == "test")
			h := agent.HandlerWithLive(reg, profiles, live)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if sock := os.Getenv("MODEL_GATEWAY_CONTROL_SOCKET"); sock != "" {
				ctrl := &agent.ControlServer{Path: sock, Registry: reg, Live: live, Profiles: profiles}
				go func() {
					if err := ctrl.ListenAndServe(ctx); err != nil {
						slog.Error("model-gateway control socket failed", "err", err)
					}
				}()
			}
			srv := &http.Server{Addr: listen, Handler: h}
			go func() {
				<-ctx.Done()
				_ = srv.Close()
			}()
			slog.Info("model-gateway listening", "addr", listen, "profiles", len(profiles))
			err := srv.ListenAndServe()
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:3210", "HTTP listen address (loopback by default)")
	cmd.Flags().StringVar(&healthcheckURL, "healthcheck", "", "GET this URL and exit (Compose probe)")
	cmd.Flags().Lookup("healthcheck").NoOptDefVal = "auto"
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
