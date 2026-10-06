package api

import (
	"net/http"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var skillCatalogKeys = []string{"id", "provider", "slug", "displayName", "description", "fetchedAt", "cacheState", "pinnedCommit", "skillCount", "lockState"}
var toolkitRegistryPresetKeys = []string{"id", "name", "description", "sourceUrl", "license", "defaultRevision", "supportedScopes", "installable"}

func registerDashboardToolkitRegistry(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("GET /api/v1/toolkit-registry", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := map[string]any{}
		if provider := r.URL.Query().Get("provider"); provider != "" {
			input["provider"] = provider
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpToolkitRegistryList, input)
	})))
	mux.Handle("POST /api/v1/toolkit-registry", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpToolkitRegistryUpdate, body)
	})))))
	mux.Handle("POST /api/v1/toolkit-registry/refresh", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpToolkitRegistryRefresh, body)
	})))))
}

func projectToolkitRegistryList(obj map[string]any) map[string]any {
	return map[string]any{
		"entries": projectObjects(obj["entries"], skillCatalogKeys...),
		"presets": projectObjects(obj["presets"], toolkitRegistryPresetKeys...),
	}
}

func projectToolkitRegistryRefresh(obj map[string]any) map[string]any {
	return map[string]any{"entries": projectObjects(obj["entries"], skillCatalogKeys...)}
}

func projectToolkitRegistryUpdate(obj map[string]any) map[string]any {
	return pickKeys(obj, "provider", "slug", "action", "revisionId")
}
