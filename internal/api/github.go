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
	case protocol.OpMCPServerConnectionResult:
		if code == protocol.ErrorNotFound || code == protocol.ErrorForbidden {
			return "unknown or inaccessible MCP server"
		}
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "The MCP gateway is temporarily unavailable."
		}
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
	case protocol.OpSkillList, protocol.OpSkillBulk, protocol.OpSkillSearch:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "The skill registry is temporarily unavailable."
		}
	case protocol.OpSkillGet, protocol.OpSkillUpdate, protocol.OpSkillArchive, protocol.OpSkillRestore, protocol.OpSkillUsage,
		protocol.OpSkillRevisionList, protocol.OpSkillRevisionGet, protocol.OpSkillRevisionDiff, protocol.OpSkillRevisionCreate, protocol.OpSkillRevisionFork:
		if code == protocol.ErrorNotFound {
			return "Skill not found."
		}
		if code == protocol.ErrorConflict {
			return "This skill changed after you opened it."
		}
		if (op == protocol.OpSkillCreateCustom || op == protocol.OpSkillRevisionFork) && code == protocol.ErrorConflict {
			return "A skill with this name already exists."
		}
	case protocol.OpSkillCreateCustom:
		if code == protocol.ErrorConflict {
			return "A skill with this name already exists."
		}
	case protocol.OpSkillArchiveImport:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "The skill registry is temporarily unavailable."
		}
		if code == protocol.ErrorInvalidInput {
			return "The skill archive could not be imported."
		}
	case protocol.OpSkillImportStart:
		if code == protocol.ErrorConflict {
			return "This import already started."
		}
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "The provider is temporarily unavailable."
		}
	case protocol.OpSkillImportStatus:
		if code == protocol.ErrorNotFound {
			return "Import job not found."
		}
	case protocol.OpSkillImportCancel:
		if code == protocol.ErrorNotFound {
			return "Import job not found."
		}
		if code == protocol.ErrorConflict {
			return "This import already finished."
		}
	case protocol.OpSkillSetList:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "Skill sets are temporarily unavailable."
		}
	case protocol.OpSkillSetGet, protocol.OpSkillSetPreview:
		if code == protocol.ErrorNotFound {
			return "Skill set not found."
		}
		if code == protocol.ErrorConflict {
			return "This skill set changed after you opened it."
		}
	case protocol.OpSkillSetCreate:
		if code == protocol.ErrorConflict {
			return "A skill set with this name already exists."
		}
	case protocol.OpSkillSetUpdate:
		if code == protocol.ErrorConflict {
			return "This skill set changed after you opened it."
		}
	case protocol.OpSkillSetDelete:
		if code == protocol.ErrorConflict {
			return "This skill set is still used by a workspace."
		}
	case protocol.OpSettingsGet, protocol.OpSettingsUpdate:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "Instance settings are temporarily unavailable."
		}
		if op == protocol.OpSettingsUpdate && code == protocol.ErrorInvalidInput {
			return "The default network profile must be network-none or dependency-access."
		}
	case protocol.OpSettingsNetworkCheck:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "The egress readiness check is temporarily unavailable."
		}
	case protocol.OpToolkitsList:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "Toolkits list is temporarily unavailable."
		}
	case protocol.OpToolkitsPreview:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "Toolkits preview is temporarily unavailable."
		}
	case protocol.OpToolkitRegistryList, protocol.OpToolkitRegistryUpdate, protocol.OpToolkitRegistryRefresh:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "The toolkit registry is temporarily unavailable."
		}
	case protocol.OpIntegrationCredentialList, protocol.OpIntegrationCredentialCreate, protocol.OpIntegrationCredentialRotate, protocol.OpIntegrationCredentialDelete, protocol.OpTypesafeStatus:
		if code == protocol.ErrorUnavailable || code == protocol.ErrorDependencyEgressUnavailable {
			return "Integration credentials are temporarily unavailable."
		}
		if code == protocol.ErrorNotFound {
			return "Integration credential not found."
		}
		if code == protocol.ErrorConflict {
			return "This integration credential already exists or changed after you opened it."
		}
	}
	return dashboardMessage(code)
}
