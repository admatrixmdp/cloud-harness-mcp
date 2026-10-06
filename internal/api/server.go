package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
)

const maxAccessVerifications = 32

// Options configure the public HTTP assembly. Bearer is optional: when empty,
// the Go-port slice does not require Authorization (local tests). Production
// owner-bearer must set MCP_BEARER_TOKEN. Cloudflare Access never treats an
// opaque client bearer as identity.
type Options struct {
	BearerToken    string
	OwnerID        string
	Mode           auth.Mode
	AccessVerifier *auth.AccessVerifier
	Runner         *mcp.RunnerClient
	Security       SecurityConfig
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
	mux.Handle("/mcp-gateway", authenticate(opts, mcp.GatewayHandlerWith(mcp.HandlerOptions{Runner: opts.Runner})))
	inner := securityHeaders(mux)
	if len(opts.Security.PublicHosts) > 0 {
		return RequestSecurity(opts.Security, inner)
	}
	return inner
}

func authenticate(opts Options, next http.Handler) http.Handler {
	if opts.Mode == auth.ModeCloudflareAccess {
		return withAccess(opts.AccessVerifier, next)
	}
	return withBearer(opts.BearerToken, opts.OwnerID, next)
}

func withAccess(verifier *auth.AccessVerifier, next http.Handler) http.Handler {
	var active atomic.Int32
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verifier == nil {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		authz := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(authz, "Bearer ")), "chm_key_") {
			writeAuthFailed(w)
			return
		}
		if active.Load() >= maxAccessVerifications {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "too_many_requests"})
			return
		}
		active.Add(1)
		defer active.Add(-1)
		assertion := r.Header.Get("Cf-Access-Jwt-Assertion")
		id, err := verifier.Verify(assertion)
		if err != nil {
			reason := auth.ReasonOf(err)
			path := r.URL.Path
			if len(path) > 256 {
				path = path[:256]
			}
			slog.Warn("access assertion rejected", "reason", string(reason), "path", path)
			writeAuthFailed(w)
			return
		}
		ctx := auth.WithIdentity(r.Context(), auth.RequestIdentity{
			Mode:    auth.ModeCloudflareAccess,
			Issuer:  id.Principal.Issuer,
			Subject: id.Principal.Subject,
			Email:   id.Email,
			Name:    id.Name,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func withBearer(token, ownerID string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if !strings.EqualFold(got, "Bearer "+token) {
			writeAuthFailed(w)
			return
		}
		if ownerID == "" {
			ownerID = "owner"
		}
		ctx := auth.WithIdentity(r.Context(), auth.RequestIdentity{
			Mode:    auth.ModeOwnerBearer,
			OwnerID: ownerID,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeAuthFailed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="cloud-harness-mcp"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "authentication_failed"})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
