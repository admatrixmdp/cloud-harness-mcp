package api

import (
	"net/http"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var integrationCredentialKeys = []string{"id", "integration", "label", "status", "activeVersion", "generation", "createdAt", "updatedAt"}

func registerDashboardIntegrations(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("GET /api/v1/integration-credentials", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpIntegrationCredentialList, map[string]any{})
	})))
	mux.Handle("POST /api/v1/integration-credentials", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpIntegrationCredentialCreate, body)
	})))))
	mux.Handle("PUT /api/v1/integration-credentials/{id}/rotate", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("id"), protocol.PrefixIntegrationCredential)
		if !ok {
			return
		}
		body["credentialId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpIntegrationCredentialRotate, body)
	})))))
	mux.Handle("DELETE /api/v1/integration-credentials/{id}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("id"), protocol.PrefixIntegrationCredential)
		if !ok {
			return
		}
		body["credentialId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpIntegrationCredentialDelete, body)
	})))))
	mux.Handle("GET /api/v1/typesafe", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpTypesafeStatus, map[string]any{})
	})))
}

func projectIntegrationCredentialList(obj map[string]any) map[string]any {
	return map[string]any{"credentials": projectObjects(obj["credentials"], integrationCredentialKeys...)}
}
