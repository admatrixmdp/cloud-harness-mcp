package api

import (
	"net/http"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var modelCredentialKeys = []string{"id", "label", "provider", "authMode", "activeVersion", "status", "syncStatus", "createdAt", "updatedAt"}
var modelProfileKeys = []string{"id", "displayName", "credentialId", "desiredRevisionId", "activeRevisionId", "generation", "status", "createdAt", "updatedAt"}
var modelRevisionKeys = []string{"id", "profileId", "credentialId", "model", "apiMode", "downstreamPath", "upstreamUrl", "pricing", "limits", "maxProxyOperations", "digest", "createdAt"}
var modelStatusKeys = []string{"gatewaySynced", "gatewayBootId", "lastSyncTime", "activeProfileCount", "activeCredentialCount", "error"}

func registerDashboardModels(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("GET /api/v1/provider-credentials", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpModelCredentialList, map[string]any{})
	})))
	mux.Handle("POST /api/v1/provider-credentials", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpModelCredentialCreate, body)
	})))))
	mux.Handle("PUT /api/v1/provider-credentials/{id}/rotate", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("id"), protocol.PrefixModelCredential)
		if !ok {
			return
		}
		body["credentialId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpModelCredentialRotate, body)
	})))))
	mux.Handle("DELETE /api/v1/provider-credentials/{id}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("id"), protocol.PrefixModelCredential)
		if !ok {
			return
		}
		body["credentialId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpModelCredentialDelete, body)
	})))))
	mux.Handle("GET /api/v1/agent-model-profiles", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpModelProfileList, map[string]any{})
	})))
	mux.Handle("POST /api/v1/agent-model-profiles", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpModelProfileCreate, body)
	})))))
	mux.Handle("PATCH /api/v1/agent-model-profiles/{id}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["profileId"] = r.PathValue("id")
		proxyDashboard(w, r, opts.Runner, protocol.OpModelProfileUpdate, body)
	})))))
	mux.Handle("POST /api/v1/agent-model-profiles/{id}/activate", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["profileId"] = r.PathValue("id")
		proxyDashboard(w, r, opts.Runner, protocol.OpModelProfileActivate, body)
	})))))
	mux.Handle("POST /api/v1/agent-model-profiles/{id}/disable", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["profileId"] = r.PathValue("id")
		proxyDashboard(w, r, opts.Runner, protocol.OpModelProfileDisable, body)
	})))))
	mux.Handle("DELETE /api/v1/agent-model-profiles/{id}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["profileId"] = r.PathValue("id")
		proxyDashboard(w, r, opts.Runner, protocol.OpModelProfileDelete, body)
	})))))
	mux.Handle("GET /api/v1/agent-model-config-status", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpModelConfigStatus, map[string]any{})
	})))
}

func projectModelProfile(obj map[string]any) map[string]any {
	out := pickKeys(obj, modelProfileKeys...)
	if nested, ok := obj["activeRevision"].(map[string]any); ok && nested != nil {
		out["activeRevision"] = pickKeys(nested, modelRevisionKeys...)
	} else {
		out["activeRevision"] = nil
	}
	return out
}

func projectModelProfiles(raw any) []map[string]any {
	switch rows := raw.(type) {
	case []map[string]any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, projectModelProfile(row))
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			obj, _ := row.(map[string]any)
			out = append(out, projectModelProfile(obj))
		}
		return out
	default:
		return []map[string]any{}
	}
}

func projectModelStatus(obj map[string]any) map[string]any {
	if nested, ok := obj["status"].(map[string]any); ok {
		return map[string]any{"status": pickKeys(nested, modelStatusKeys...)}
	}
	return map[string]any{"status": pickKeys(obj, modelStatusKeys...)}
}
