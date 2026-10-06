package api

import (
	"net/http"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const githubUnavailable = "GitHub authorization is unavailable. Check the GitHub App credentials in the runner configuration, then retry."

func registerDashboardGitHub(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("GET /api/v1/github", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpGitHubStatus, map[string]any{})
	})))
	mux.Handle("POST /api/v1/github/setup", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpGitHubSetupBegin, body)
	})))))
	mux.Handle("POST /api/v1/github/complete", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpGitHubSetupComplete, body)
	})))))
	mux.Handle("POST /api/v1/github/reconcile", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpGitHubReconcile, body)
	})))))
	mux.Handle("DELETE /api/v1/github/installations/{installationId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["installationId"] = r.PathValue("installationId")
		proxyDashboard(w, r, opts.Runner, protocol.OpGitHubDisconnect, body)
	})))))
	mux.Handle("POST /api/v1/github/disconnect", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpGitHubDisconnect, body)
	})))))
}

func projectGitHubStatus(obj map[string]any) map[string]any {
	installKeys := []string{"appId", "installationId", "accountId", "accountLogin", "status", "generation", "createdAt", "updatedAt", "checkedAt"}
	repoKeys := []string{"installationId", "owner", "repository", "contents", "status", "generation", "createdAt", "updatedAt", "checkedAt"}
	installations := projectObjects(obj["installations"], installKeys...)
	if len(installations) == 0 {
		if nested, ok := obj["installation"].(map[string]any); ok && nested != nil {
			picked := pickKeys(nested, installKeys...)
			if len(picked) > 0 {
				installations = []map[string]any{picked}
			}
		}
	}
	var installation any
	if len(installations) > 0 {
		installation = installations[0]
	} else if nested, ok := obj["installation"].(map[string]any); ok && nested != nil {
		installation = pickKeys(nested, installKeys...)
	} else {
		installation = nil
	}
	return map[string]any{
		"configured":    obj["configured"] == true,
		"installation":  installation,
		"installations": installations,
		"repositories":  projectObjects(obj["repositories"], repoKeys...),
	}
}

func dashboardMessageFor(op protocol.Operation, code protocol.ErrorCode) string {
	switch op {
	case protocol.OpGitHubStatus, protocol.OpGitHubSetupBegin:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return githubUnavailable
		}
	case protocol.OpGitHubSetupComplete:
		switch code {
		case protocol.ErrorUnavailable, protocol.ErrorDependencyEgressUnavailable:
			return githubUnavailable
		case protocol.ErrorInvalidInput:
			return "The GitHub App connection could not be completed. Start the connection again."
		case protocol.ErrorNotFound:
			return "GitHub installation not found."
		}
	case protocol.OpGitHubReconcile:
		switch code {
		case protocol.ErrorUnavailable, protocol.ErrorDependencyEgressUnavailable:
			return githubUnavailable
		case protocol.ErrorNotFound:
			return "GitHub installation not found."
		}
	case protocol.OpGitHubDisconnect:
		if code == protocol.ErrorNotFound {
			return "GitHub installation not found."
		}
	case protocol.OpModelCredentialList, protocol.OpModelCredentialCreate, protocol.OpModelCredentialRotate, protocol.OpModelCredentialDelete,
		protocol.OpModelProfileList, protocol.OpModelProfileCreate, protocol.OpModelProfileUpdate, protocol.OpModelProfileActivate, protocol.OpModelProfileDisable, protocol.OpModelProfileDelete,
		protocol.OpModelConfigStatus:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "Model profile operations are temporarily unavailable."
		}
		if code == protocol.ErrorNotFound {
			return "Model credential or profile not found."
		}
	}
	return dashboardMessage(code)
}
