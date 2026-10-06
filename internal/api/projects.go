package api

import (
	"net/http"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func registerDashboardProjects(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("GET /api/v1/projects", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpProjectList, map[string]any{})
	})))
	mux.Handle("POST /api/v1/projects", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpProjectCreate, body)
	})))))
	mux.Handle("PATCH /api/v1/projects/{projectId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("projectId"), protocol.PrefixProject)
		if !ok {
			return
		}
		body["projectId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpProjectUpdate, body)
	})))))
	mux.Handle("DELETE /api/v1/projects/{projectId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("projectId"), protocol.PrefixProject)
		if !ok {
			return
		}
		body["projectId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpProjectDelete, body)
	})))))
	mux.Handle("GET /api/v1/projects/{projectId}/environments", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("projectId"), protocol.PrefixProject)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpEnvironmentList, map[string]any{"projectId": id})
	})))
	mux.Handle("POST /api/v1/projects/{projectId}/environments", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("projectId"), protocol.PrefixProject)
		if !ok {
			return
		}
		body["projectId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpEnvironmentCreate, body)
	})))))
	mux.Handle("PATCH /api/v1/environments/{environmentId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("environmentId"), protocol.PrefixEnvironment)
		if !ok {
			return
		}
		body["environmentId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpEnvironmentUpdate, body)
	})))))
	mux.Handle("DELETE /api/v1/environments/{environmentId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("environmentId"), protocol.PrefixEnvironment)
		if !ok {
			return
		}
		body["environmentId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpEnvironmentDelete, body)
	})))))
	mux.Handle("GET /api/v1/environments/{environmentId}/secrets", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("environmentId"), protocol.PrefixEnvironment)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSecretList, map[string]any{"environmentId": id})
	})))
	mux.Handle("POST /api/v1/environments/{environmentId}/secrets", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("environmentId"), protocol.PrefixEnvironment)
		if !ok {
			return
		}
		body["environmentId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSecretCreate, body)
	})))))
	mux.Handle("POST /api/v1/environments/{environmentId}/secrets/bulk", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("environmentId"), protocol.PrefixEnvironment)
		if !ok {
			return
		}
		body["environmentId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSecretBulkApply, body)
	})))))
	mux.Handle("PUT /api/v1/environments/{environmentId}/secrets/{name}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("environmentId"), protocol.PrefixEnvironment)
		if !ok {
			return
		}
		body["environmentId"] = id
		body["name"] = r.PathValue("name")
		proxyDashboard(w, r, opts.Runner, protocol.OpSecretRotate, body)
	})))))
	mux.Handle("PATCH /api/v1/environments/{environmentId}/secrets/{name}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("environmentId"), protocol.PrefixEnvironment)
		if !ok {
			return
		}
		body["environmentId"] = id
		body["name"] = r.PathValue("name")
		proxyDashboard(w, r, opts.Runner, protocol.OpSecretUpdate, body)
	})))))
	mux.Handle("DELETE /api/v1/environments/{environmentId}/secrets/{name}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("environmentId"), protocol.PrefixEnvironment)
		if !ok {
			return
		}
		body["environmentId"] = id
		body["name"] = r.PathValue("name")
		proxyDashboard(w, r, opts.Runner, protocol.OpSecretDelete, body)
	})))))
	mux.Handle("GET /api/v1/secrets", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpGlobalSecretList, map[string]any{})
	})))
	mux.Handle("POST /api/v1/secrets", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpGlobalSecretCreate, body)
	})))))
	mux.Handle("POST /api/v1/secrets/bulk", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpGlobalSecretBulkApply, body)
	})))))
	mux.Handle("PUT /api/v1/secrets/{name}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["name"] = r.PathValue("name")
		proxyDashboard(w, r, opts.Runner, protocol.OpGlobalSecretRotate, body)
	})))))
	mux.Handle("PATCH /api/v1/secrets/{name}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["name"] = r.PathValue("name")
		proxyDashboard(w, r, opts.Runner, protocol.OpGlobalSecretUpdate, body)
	})))))
	mux.Handle("DELETE /api/v1/secrets/{name}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["name"] = r.PathValue("name")
		proxyDashboard(w, r, opts.Runner, protocol.OpGlobalSecretDelete, body)
	})))))
}

func requirePrefixedID(w http.ResponseWriter, id, prefix string) (string, bool) {
	if !protocol.ValidOpaqueID(prefix, id) {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return "", false
	}
	return id, true
}

func projectSecretList(obj map[string]any) map[string]any {
	readiness := map[string]any{}
	if nested, ok := obj["readiness"].(map[string]any); ok {
		readiness = pickKeys(nested, "ready", "error")
	}
	return map[string]any{
		"secrets":   projectObjects(obj["secrets"], secretKeys...),
		"readiness": readiness,
	}
}
