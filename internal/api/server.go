package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
)

// Options configure the public HTTP assembly. Bearer is optional: when empty,
// the Go-port slice does not require Authorization (local tests). Production
// must set MCP_BEARER_TOKEN.
type Options struct {
	BearerToken string
	Runner      *mcp.RunnerClient
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
	mux.Handle("/mcp", withBearer(opts.BearerToken, mcp.HandlerWith(mcp.HandlerOptions{Runner: opts.Runner})))
	mux.Handle("/mcp-gateway", withBearer(opts.BearerToken, mcp.GatewayHandler()))
	return securityHeaders(mux)
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
