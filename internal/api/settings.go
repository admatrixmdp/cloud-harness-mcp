package api

import (
	"net/http"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var toolkitPresetKeys = []string{"id", "name", "description", "defaultRevision", "adapterVersion", "license", "sourceUrl", "supportedScopes", "supportedTargets", "requiredSecret", "activation"}
var licensedKitKeys = []string{"kind", "kitId", "name", "description", "defaultChannel", "available", "credentialReady", "requiresCredentialSecret", "supportedScopes", "activation", "verification"}

func registerDashboardSettings(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("GET /api/v1/toolkits", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpToolkitsList, map[string]any{})
	})))
	mux.Handle("POST /api/v1/toolkits/preview", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpToolkitsPreview, body)
	})))))
	mux.Handle("GET /api/v1/settings", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpSettingsGet, map[string]any{})
	})))
	mux.Handle("POST /api/v1/settings", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		if !validSettingsUpdate(body) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":   "invalid_input",
				"message": "The default network profile must be network-none or dependency-access.",
			})
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSettingsUpdate, body)
	})))))
	mux.Handle("POST /api/v1/settings/network-check", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSettingsNetworkCheck, body)
	})))))
}

func validSettingsUpdate(body map[string]any) bool {
	if len(body) != 1 {
		return false
	}
	value, ok := body["defaultNetworkProfile"]
	if !ok {
		return false
	}
	if value == nil {
		return true
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	return protocol.NetworkProfile(text).Valid()
}

func projectSettings(obj map[string]any) map[string]any {
	nested, _ := obj["defaultNetworkProfile"].(map[string]any)
	return map[string]any{"defaultNetworkProfile": pickKeys(nested, "value", "source")}
}

func projectToolkitsList(obj map[string]any) map[string]any {
	return map[string]any{
		"toolkits":     projectObjects(obj["toolkits"], toolkitPresetKeys...),
		"licensedKits": projectObjects(obj["licensedKits"], licensedKitKeys...),
	}
}

func projectToolkitsPreview(obj map[string]any) map[string]any {
	return pickKeys(obj, "requestFingerprint", "toolkitsCount")
}

func projectNetworkCheck(obj map[string]any) map[string]any {
	out := map[string]any{"ready": obj["ready"] == true}
	if obj["reason"] == nil {
		out["reason"] = nil
	} else if reason, ok := obj["reason"].(string); ok {
		out["reason"] = reason
	}
	return out
}
