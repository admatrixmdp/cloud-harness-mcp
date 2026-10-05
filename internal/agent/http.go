package agent

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// Handler serves /healthz and lease-gated model routes. Provider credentials
// never appear in logs or responses.
func Handler(reg *Registry, profiles map[string]Profile) http.Handler {
	if reg == nil {
		reg = NewRegistry()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Header().Set("cache-control", "no-store")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		serveLease(w, r, reg, profiles, "/v1/chat/completions")
	})
	mux.HandleFunc("POST /v1/responses", func(w http.ResponseWriter, r *http.Request) {
		serveLease(w, r, reg, profiles, "/v1/responses")
	})
	return mux
}

func serveLease(w http.ResponseWriter, r *http.Request, reg *Registry, profiles map[string]Profile, path string) {
	profileID := r.Header.Get("x-model-profile")
	agentID := r.Header.Get("x-agent-id")
	if _, ok := profiles[profileID]; !ok || !ValidAgentID(agentID) {
		writeErr(w, http.StatusUnauthorized, "invalid_gateway_lease")
		return
	}
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || token == "" {
		writeErr(w, http.StatusUnauthorized, "invalid_gateway_lease")
		return
	}
	if _, err := reg.Consume(token, agentID, profileID); err != nil {
		slog.Info("model_gateway_denied", "reason", err.Error(), "agentId", agentID, "profileId", profileID)
		writeErr(w, http.StatusUnauthorized, "invalid_gateway_lease")
		return
	}
	profile := profiles[profileID]
	if !profile.hasUpstream() {
		writeErr(w, http.StatusServiceUnavailable, "upstream_not_wired")
		return
	}
	proxyUpstream(w, r, profile)
	_ = path
}

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": code})
}
