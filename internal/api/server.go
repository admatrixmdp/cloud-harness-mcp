package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
)

// Options configure the public HTTP assembly. Bearer is optional: when empty,
// the Go-port slice does not require Authorization (local tests). Production
// must set MCP_BEARER_TOKEN.
type Options struct {
	BearerToken    string
	Mode           auth.Mode
	AccessVerifier *auth.AccessVerifier
	Runner         *mcp.RunnerClient
}

// Handler is the API mux. It must not expose a Docker socket.
func Handler(opts Options) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ready := opts.Runner != nil && opts.Runner.Ready(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.Handle("/mcp", authenticate(opts, mcp.HandlerWith(mcp.HandlerOptions{Runner: opts.Runner})))
	mux.Handle("/mcp-gateway", authenticate(opts, mcp.GatewayHandler()))
	return securityHeaders(mux)
}

func authenticate(opts Options, next http.Handler) http.Handler {
	if opts.Mode == auth.ModeCloudflareAccess {
		return withAccess(opts.AccessVerifier, next)
	}
	return withBearer(opts.BearerToken, next)
}

func withAccess(verifier *auth.AccessVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verifier == nil {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		assertion := r.Header.Get("Cf-Access-Jwt-Assertion")
		if _, err := verifier.Verify(assertion); err != nil {
			reason := auth.ReasonOf(err)
			slog.Warn("access assertion rejected", "reason", string(reason), "path", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "authentication_failed"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withBearer(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if !strings.EqualFold(got, "Bearer "+token) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":        false,
				"message":   "authentication failed",
				"error":     map[string]any{"code": "AUTHENTICATION_FAILED", "message": "authentication failed", "retryable": false},
				"truncated": false,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
