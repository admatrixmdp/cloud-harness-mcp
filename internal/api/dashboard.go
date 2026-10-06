package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

var mutationMethods = map[string]struct{}{
	http.MethodPost: {}, http.MethodPut: {}, http.MethodPatch: {}, http.MethodDelete: {},
}

func dashboardHandler(opts Options, sessions *Sessions) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/session", sessions.bootstrap)
	mux.Handle("GET /api/v1/privilege-grants", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpPrivilegeGrantList, map[string]any{
			"workspaceId": r.URL.Query().Get("workspaceId"),
		})
	})))
	mux.Handle("POST /api/v1/privilege-grants/{grantId}/approve", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpPrivilegeGrantApprove, map[string]any{
			"grantId": r.PathValue("grantId"),
		})
	})))))
	mux.Handle("POST /api/v1/privilege-grants/{grantId}/reject", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpPrivilegeGrantReject, map[string]any{
			"grantId": r.PathValue("grantId"),
		})
	})))))
	mux.Handle("GET /api/v1/workspaces", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpWorkspaceList, pageQuery(r))
	})))
	mux.Handle("POST /api/v1/workspaces", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := decodeObject(r)
		if err != nil {
			writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpWorkspaceOpen, body)
	})))))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpWorkspaceDetail, map[string]any{
			"workspaceId": r.PathValue("workspaceId"),
		})
	})))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/files", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := pageQuery(r)
		input["workspaceId"] = r.PathValue("workspaceId")
		path := r.URL.Query().Get("path")
		if path == "" {
			path = "."
		}
		input["path"] = path
		proxyDashboard(w, r, opts.Runner, protocol.OpFilesList, input)
	})))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/files/content", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := map[string]any{
			"workspaceId": r.PathValue("workspaceId"),
			"path":        r.URL.Query().Get("path"),
		}
		if offset := queryInt(r, "offset"); offset > 0 {
			input["offset"] = offset
		}
		if limit := queryInt(r, "limit"); limit > 0 {
			input["limit"] = limit
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpFilesRead, input)
	})))
	mux.Handle("PUT /api/v1/workspaces/{workspaceId}/files/content", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFileMutation(w, r, opts.Runner, protocol.OpFilesWrite)
	})))))
	mux.Handle("PATCH /api/v1/workspaces/{workspaceId}/files/content", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFileMutation(w, r, opts.Runner, protocol.OpFilesApplyPatch)
	})))))
	mux.Handle("DELETE /api/v1/workspaces/{workspaceId}/files/content", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFileMutation(w, r, opts.Runner, protocol.OpFilesDelete)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/files/move", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFileMutation(w, r, opts.Runner, protocol.OpFilesMove)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/files/directory", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyFileMutation(w, r, opts.Runner, protocol.OpFilesMkdir)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/close", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := decodeObject(r)
		if err != nil {
			writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
			return
		}
		body["workspaceId"] = r.PathValue("workspaceId")
		proxyDashboard(w, r, opts.Runner, protocol.OpWorkspaceCloseFenced, body)
	})))))
	mux.Handle("GET /api/v1/knowledge", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardList, knowledgeListQuery(r))
	})))
	mux.Handle("POST /api/v1/knowledge/search", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardSearch, body)
	})))))
	mux.Handle("POST /api/v1/knowledge/links", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardLinkCreate, body)
	})))))
	mux.Handle("DELETE /api/v1/knowledge/links", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardLinkDelete, body)
	})))))
	mux.Handle("GET /api/v1/knowledge-graph", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardGraph, knowledgeGraphQuery(r))
	})))
	mux.Handle("GET /api/v1/knowledge/{id}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardGet, map[string]any{"id": r.PathValue("id")})
	})))
	mux.Handle("POST /api/v1/knowledge", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardCreate, body)
	})))))
	mux.Handle("PUT /api/v1/knowledge/{id}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["id"] = r.PathValue("id")
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardUpdate, body)
	})))))
	mux.Handle("DELETE /api/v1/knowledge/{id}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["id"] = r.PathValue("id")
		proxyDashboard(w, r, opts.Runner, protocol.OpKnowledgeDashboardDelete, body)
	})))))
	mux.Handle("GET /api/v1/mcp-servers", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpMCPServerList, map[string]any{})
	})))
	mux.Handle("POST /api/v1/mcp-servers", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		if rejectAuthenticatedSSE(w, body) || rejectUnsafeEndpoint(w, body, opts) {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpMCPServerCreate, body)
	})))))
	mux.Handle("GET /api/v1/mcp-servers/{serverId}/logs", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverID, ok := requireServerID(w, r)
		if !ok {
			return
		}
		input := pageQuery(r)
		input["serverId"] = serverID
		if limit := queryInt(r, "limit"); limit > 0 {
			input["limit"] = limit
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpMCPGatewayTraceList, input)
	})))
	mux.Handle("GET /api/v1/mcp-servers/{serverId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverID, ok := requireServerID(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpMCPServerGet, map[string]any{"serverId": serverID})
	})))
	mux.Handle("PATCH /api/v1/mcp-servers/{serverId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverID, ok := requireServerID(w, r)
		if !ok {
			return
		}
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body = mergeServerID(body, serverID)
		if rejectAuthenticatedSSE(w, body) || rejectUnsafeEndpoint(w, body, opts) {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpMCPServerUpdate, body)
	})))))
	mux.Handle("DELETE /api/v1/mcp-servers/{serverId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverID, ok := requireServerID(w, r)
		if !ok {
			return
		}
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpMCPServerDelete, mergeServerID(body, serverID))
	})))))
	mux.Handle("POST /api/v1/mcp-servers/{serverId}/enabled", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverID, ok := requireServerID(w, r)
		if !ok {
			return
		}
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpMCPServerSetEnabled, mergeServerID(body, serverID))
	})))))
	mux.Handle("PUT /api/v1/mcp-servers/{serverId}/permissions", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverID, ok := requireServerID(w, r)
		if !ok {
			return
		}
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		delete(body, "default")
		proxyDashboard(w, r, opts.Runner, protocol.OpMCPServerSetPermissions, mergeServerID(body, serverID))
	})))))
	mux.Handle("GET /api/v1/artifacts", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpArtifactList, pageQuery(r))
	})))
	mux.Handle("POST /api/v1/artifacts", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpArtifactSnapshot, body)
	})))))
	mux.Handle("GET /api/v1/artifacts/{artifactId}/download", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloadArtifact(w, r, opts.Runner)
	})))
	mux.Handle("GET /api/v1/artifacts/{artifactId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		artifactID, ok := requireArtifactID(w, r)
		if !ok {
			return
		}
		input := map[string]any{"artifactId": artifactID}
		if offset := queryInt(r, "offset"); offset > 0 {
			input["offset"] = offset
		}
		if limit := queryInt(r, "limit"); limit > 0 {
			input["limit"] = limit
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpArtifactRead, input)
	})))
	mux.Handle("POST /api/v1/artifacts/{artifactId}/restore", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		artifactID, ok := requireArtifactID(w, r)
		if !ok {
			return
		}
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["artifactId"] = artifactID
		proxyDashboard(w, r, opts.Runner, protocol.OpArtifactRestore, body)
	})))))
	mux.Handle("DELETE /api/v1/artifacts/{artifactId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		artifactID, ok := requireArtifactID(w, r)
		if !ok {
			return
		}
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["artifactId"] = artifactID
		proxyDashboard(w, r, opts.Runner, protocol.OpArtifactDelete, body)
	})))))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/artifacts", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listWorkspaceArtifacts(w, r, opts.Runner)
	})))
	mux.Handle("GET /api/v1/agents", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listDashboardAgents(w, r, opts.Runner)
	})))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/agents", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := map[string]any{"workspaceId": r.PathValue("workspaceId")}
		if status := r.URL.Query().Get("status"); status != "" {
			input["status"] = status
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpAgentList, input)
	})))
	mux.Handle("GET /api/v1/agents/{agentId}/logs", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID, ok := requireAgentID(w, r)
		if !ok {
			return
		}
		input := map[string]any{"agentId": agentID}
		if workspaceID := r.URL.Query().Get("workspaceId"); workspaceID != "" {
			input["workspaceId"] = workspaceID
		}
		if cursor := r.URL.Query().Get("cursor"); cursor != "" {
			input["cursor"] = cursor
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpAgentLogs, input)
	})))
	mux.Handle("GET /api/v1/agents/{agentId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID, ok := requireAgentID(w, r)
		if !ok {
			return
		}
		input := map[string]any{"agentId": agentID}
		if workspaceID := r.URL.Query().Get("workspaceId"); workspaceID != "" {
			input["workspaceId"] = workspaceID
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpAgentStatus, input)
	})))
	mux.Handle("POST /api/v1/agents/{agentId}/messages", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID, ok := requireAgentID(w, r)
		if !ok {
			return
		}
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["agentId"] = agentID
		proxyDashboard(w, r, opts.Runner, protocol.OpAgentMessage, body)
	})))))
	mux.Handle("POST /api/v1/agents/{agentId}/cancel", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID, ok := requireAgentID(w, r)
		if !ok {
			return
		}
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		body["agentId"] = agentID
		proxyDashboard(w, r, opts.Runner, protocol.OpAgentCancel, body)
	})))))
	mux.Handle("GET /api/v1/activity", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeActivity(w, r, opts.Runner, "")
	})))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/activity", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeActivity(w, r, opts.Runner, r.PathValue("workspaceId"))
	})))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/skills", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspace(w, r, opts.Runner, protocol.OpSkillsList, nil)
	})))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/skills/{name}/run", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpSkillsRun, map[string]any{"name": r.PathValue("name")})
	})))))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/hooks", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspace(w, r, opts.Runner, protocol.OpHooksList, map[string]any{"includeInactive": true})
	})))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/hooks/run", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpHooksRun, nil)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/hooks/activate", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpHooksActivate, nil)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/hooks/deactivate", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpHooksDeactivate, nil)
	})))))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/deployments", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspace(w, r, opts.Runner, protocol.OpDeploymentsList, nil)
	})))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/deployments/run", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpDeploymentsRun, nil)
	})))))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/git/status", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspace(w, r, opts.Runner, protocol.OpGitStatus, nil)
	})))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/git/diff", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := map[string]any{"staged": r.URL.Query().Get("staged") == "true"}
		if path := r.URL.Query().Get("path"); path != "" {
			input["path"] = path
		}
		proxyWorkspace(w, r, opts.Runner, protocol.OpGitDiff, input)
	})))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/git/log", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := map[string]any{}
		if limit := queryInt(r, "limit"); limit > 0 {
			input["limit"] = limit
		}
		proxyWorkspace(w, r, opts.Runner, protocol.OpGitLog, input)
	})))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/git/fetch", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpGitFetch, nil)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/git/pull", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpGitPull, nil)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/git/checkout", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpGitCheckout, nil)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/git/branch", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpGitBranch, nil)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/git/merge", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpGitMerge, nil)
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/git/rebase", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpGitRebase, nil)
	})))))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/worktrees", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspace(w, r, opts.Runner, protocol.OpWorktreesList, nil)
	})))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/worktrees", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpWorktreesCreate, nil)
	})))))
	mux.Handle("DELETE /api/v1/workspaces/{workspaceId}/worktrees/{name}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !validWorktreeName(name) {
			writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
			return
		}
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpWorktreesRemove, map[string]any{"name": name})
	})))))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/tasks/graph", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspace(w, r, opts.Runner, protocol.OpTasksGraph, nil)
	})))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/tasks/{taskId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		taskID, ok := requireTaskID(w, r)
		if !ok {
			return
		}
		input := map[string]any{"taskId": taskID}
		if cursor := r.URL.Query().Get("cursor"); cursor != "" {
			input["cursor"] = cursor
		}
		proxyWorkspace(w, r, opts.Runner, protocol.OpTasksStatus, input)
	})))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/tasks/{taskId}/cancel", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		taskID, ok := requireTaskID(w, r)
		if !ok {
			return
		}
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpTasksCancel, map[string]any{"taskId": taskID})
	})))))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/sessions", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpSessionsOpen, nil)
	})))))
	mux.Handle("GET /api/v1/workspaces/{workspaceId}/sessions/{sessionId}/io", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID, ok := requireSessionID(w, r)
		if !ok {
			return
		}
		input := map[string]any{"sessionId": sessionID, "waitMs": 0}
		if cursor := r.URL.Query().Get("cursor"); cursor != "" {
			input["cursor"] = cursor
		}
		proxyWorkspace(w, r, opts.Runner, protocol.OpSessionsIO, input)
	})))
	mux.Handle("POST /api/v1/workspaces/{workspaceId}/sessions/{sessionId}/close", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID, ok := requireSessionID(w, r)
		if !ok {
			return
		}
		proxyWorkspaceMutation(w, r, opts.Runner, protocol.OpSessionsClose, map[string]any{"sessionId": sessionID})
	})))))
	return dashboardSecurity(opts.Security, mux)
}

func dashboardSecurity(cfg SecurityConfig, next http.Handler) http.Handler {
	hosts := map[string]struct{}{}
	for _, h := range cfg.PublicHosts {
		hosts[strings.ToLower(h)] = struct{}{}
	}
	origins := map[string]struct{}{}
	for _, raw := range cfg.AllowedOrigins {
		origins[strings.ToLower(strings.TrimRight(raw, "/"))] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(hosts) > 0 {
			host := hostnameFromHost(r.Host)
			if _, ok := hosts[host]; !ok {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden_host"})
				return
			}
			if raw := r.Header.Get("Origin"); raw != "" {
				if _, ok := origins[strings.ToLower(strings.TrimRight(raw, "/"))]; !ok {
					writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden_origin"})
					return
				}
			} else if _, mut := mutationMethods[r.Method]; mut {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "origin_required"})
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", dashboardCSP)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func requirePrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.IdentityFrom(r.Context()); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session_ended", "message": "Your dashboard session ended."})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, mut := mutationMethods[r.Method]; mut {
			ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
			if ct != "application/json" {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "unsupported_media_type"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func proxyDashboard(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient, op protocol.Operation, input map[string]any) {
	if runner == nil {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorUnavailable, "The workspace service is temporarily unavailable.", true))
		return
	}
	if workspace, ok := input["workspaceId"].(string); ok && workspace == "" {
		delete(input, "workspaceId")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return
	}
	var result protocol.ToolResult
	if op.Dashboard() || op.Internal() {
		result = runner.CallInternal(r.Context(), op, raw)
	} else {
		result = runner.Call(r.Context(), op, raw)
	}
	if !result.OK {
		writeDashboardFail(w, result)
		return
	}
	data := projectDashboard(op, result.Data)
	out := map[string]any{"data": data, "truncated": result.Truncated}
	if result.Cursor != "" {
		out["cursor"] = result.Cursor
	}
	writeJSON(w, http.StatusOK, out)
}

func projectDashboard(op protocol.Operation, data any) any {
	obj, _ := data.(map[string]any)
	if obj == nil {
		obj = map[string]any{}
	}
	switch op {
	case protocol.OpPrivilegeGrantList:
		return map[string]any{"grants": projectGrantList(obj["grants"])}
	case protocol.OpPrivilegeGrantApprove, protocol.OpPrivilegeGrantReject:
		return map[string]any{"grant": pickGrant(obj["grant"])}
	case protocol.OpWorkspaceList:
		return map[string]any{"workspaces": projectWorkspaceList(obj["workspaces"])}
	case protocol.OpWorkspaceOpen, protocol.OpWorkspaceStatus, protocol.OpWorkspaceDetail, protocol.OpWorkspaceClose, protocol.OpWorkspaceCloseFenced, protocol.OpWorkspaceLeaseRenew, protocol.OpWorkspaceRecover:
		return projectWorkspace(obj)
	case protocol.OpFilesList:
		return projectFilesList(obj)
	case protocol.OpFilesRead:
		return pickKeys(obj, "path", "content", "sha256", "bytes")
	case protocol.OpFilesWrite:
		return pickKeys(obj, "path", "bytes", "sha256")
	case protocol.OpFilesApplyPatch:
		return pickKeys(obj, "path", "sha256")
	case protocol.OpFilesDelete:
		return pickKeys(obj, "path", "type")
	case protocol.OpFilesMove:
		return pickKeys(obj, "source", "destination")
	case protocol.OpFilesMkdir:
		return pickKeys(obj, "path")
	case protocol.OpKnowledgeDashboardList:
		return map[string]any{"items": projectKnowledgeItems(obj["items"])}
	case protocol.OpKnowledgeDashboardGet, protocol.OpKnowledgeDashboardCreate, protocol.OpKnowledgeDashboardUpdate:
		return projectKnowledgeItem(obj)
	case protocol.OpKnowledgeDashboardDelete:
		return pickKeys(obj, "deleted")
	case protocol.OpKnowledgeDashboardSearch:
		return map[string]any{"results": projectKnowledgeHits(obj["results"])}
	case protocol.OpKnowledgeDashboardGraph:
		return map[string]any{
			"nodes":     projectObjects(obj["nodes"], "id", "kind", "scope", "title", "journalType", "tags", "updatedAt"),
			"edges":     projectObjects(obj["edges"], "id", "sourceId", "targetId", "relation", "origin", "generation", "createdAt"),
			"truncated": obj["truncated"] == true,
		}
	case protocol.OpKnowledgeDashboardLinkCreate:
		return projectKnowledgeLink(obj)
	case protocol.OpKnowledgeDashboardLinkDelete:
		return pickKeys(obj, "unlinked")
	case protocol.OpMCPServerList:
		return map[string]any{"servers": projectMCPServers(obj["servers"])}
	case protocol.OpMCPServerGet:
		return map[string]any{
			"server": projectMCPServer(obj["server"]),
			"tools":  projectObjects(obj["tools"], "id", "serverId", "qualifiedName", "upstreamName", "description", "inputSchema", "annotations", "availability", "permission", "discoveredAt"),
		}
	case protocol.OpMCPServerCreate, protocol.OpMCPServerUpdate, protocol.OpMCPServerSetEnabled, protocol.OpMCPServerSetPermissions, protocol.OpMCPServerDelete:
		return projectMCPServer(obj)
	case protocol.OpMCPGatewayTraceList:
		return map[string]any{"traces": projectObjects(obj["traces"], "id", "serverId", "serverName", "tool", "operation", "clientId", "durationMs", "status", "errorCode", "errorMessage", "requestBytes", "responseBytes", "createdAt")}
	case protocol.OpArtifactList:
		return map[string]any{"artifacts": projectObjects(obj["artifacts"], artifactKeys...)}
	case protocol.OpArtifactSnapshot, protocol.OpArtifactDelete:
		return pickKeys(obj, artifactKeys...)
	case protocol.OpArtifactRead:
		return pickKeys(obj, "artifactId", "logicalName", "offset", "bytesReturned", "totalBytes", "sha256", "eof", "content")
	case protocol.OpArtifactRestore:
		return pickKeys(obj, "artifactId", "workspaceId", "path", "sizeBytes", "sha256")
	case protocol.OpAgentList:
		return map[string]any{"agents": projectAgents(obj["agents"])}
	case protocol.OpAgentStatus:
		if nested, ok := obj["agent"].(map[string]any); ok {
			return projectAgent(nested)
		}
		return projectAgent(obj)
	case protocol.OpAgentLogs:
		return map[string]any{
			"agentId":            obj["agentId"],
			"cursor":             obj["cursor"],
			"nextCursor":         obj["nextCursor"],
			"retainedBaseCursor": obj["retainedBaseCursor"],
			"truncated":          obj["truncated"] == true,
			"hasMore":            obj["hasMore"] == true,
			"events":             projectAgentLogEvents(obj["events"]),
		}
	case protocol.OpAgentMessage, protocol.OpAgentCancel:
		return pickKeys(obj, "agentId", "status", "state", "replayed", "affectedAgentIds")
	case protocol.OpGitStatus:
		parsed := parseGitStatus(str(obj["output"]))
		parsed["output"] = boundedOutput(obj["output"])
		if parsed["output"] == nil {
			parsed["output"] = ""
		}
		return parsed
	case protocol.OpGitDiff:
		diff := boundedOutput(firstValue(obj["output"], obj["diff"]))
		out := map[string]any{"truncated": obj["truncated"] == true || strings.Contains(str(diff), "… truncated")}
		if diff != nil {
			out["diff"] = diff
		}
		if signature, _ := obj["signature"].(string); signature != "" {
			out["signature"] = signature
		}
		return out
	case protocol.OpGitLog:
		out := map[string]any{"commits": projectObjects(obj["commits"], "oid", "sha", "subject", "message", "author", "authoredAt", "date", "branch", "refs")}
		if output := boundedOutput(obj["output"]); output != nil {
			out["output"] = output
		}
		if obj["cursor"] != nil {
			out["cursor"] = obj["cursor"]
		}
		return out
	case protocol.OpWorktreesList:
		worktrees := projectObjects(obj["worktrees"], "path", "head", "branch", "name")
		if len(worktrees) == 0 {
			worktrees = parseWorktrees(str(obj["output"]))
		}
		output := boundedOutput(obj["output"])
		if output == nil {
			output = ""
		}
		return map[string]any{"worktrees": worktrees, "output": output}
	case protocol.OpGitFetch, protocol.OpGitPull, protocol.OpGitCheckout, protocol.OpGitBranch, protocol.OpGitMerge, protocol.OpGitRebase, protocol.OpWorktreesCreate, protocol.OpWorktreesRemove:
		out := pickKeys(obj, "name", "path", "head", "branch", "ref", "action")
		if output := boundedOutput(obj["output"]); output != nil {
			out["output"] = output
		}
		return out
	case protocol.OpSkillsList:
		out := map[string]any{"skills": projectObjects(obj["skills"], "name", "tier", "source", "kind", "state", "sha256", "description", "shadowed")}
		if obj["cursor"] != nil {
			out["cursor"] = obj["cursor"]
		}
		return out
	case protocol.OpSkillsRead:
		return pickKeys(obj, "name", "source", "content", "sha256", "bytes", "offset", "truncated")
	case protocol.OpHooksList:
		out := map[string]any{"hooks": projectObjects(obj["hooks"], "name", "path", "events", "active", "trigger", "description", "sha256")}
		if sha, _ := obj["manifestSha256"].(string); sha != "" {
			out["manifestSha256"] = sha
		}
		if obj["cursor"] != nil {
			out["cursor"] = obj["cursor"]
		}
		return out
	case protocol.OpDeploymentsList:
		return map[string]any{"deployments": projectObjects(obj["deployments"], "name", "cwd", "status", "lastResult", "durationMs", "error")}
	case protocol.OpSkillsRun, protocol.OpHooksRun, protocol.OpHooksActivate, protocol.OpHooksDeactivate, protocol.OpDeploymentsRun:
		out := pickKeys(obj, "name", "event", "events", "status", "exitCode", "durationMs", "error", "manifestSha256")
		if output := boundedOutput(obj["output"]); output != nil {
			out["output"] = output
		}
		return out
	case protocol.OpTasksStatus:
		task := obj
		if nested, ok := obj["task"].(map[string]any); ok {
			task = nested
		}
		out := map[string]any{"task": projectTask(task), "truncated": obj["truncated"] == true}
		if obj["cursor"] != nil {
			out["cursor"] = obj["cursor"]
		}
		return out
	case protocol.OpTasksCancel:
		task := obj
		if nested, ok := obj["task"].(map[string]any); ok {
			task = nested
		}
		return map[string]any{"task": projectTask(task)}
	case protocol.OpTasksGraph:
		edges := make([]map[string]any, 0)
		for _, edge := range asObjectList(obj["edges"]) {
			edges = append(edges, pickKeys(edge, "from", "to"))
		}
		nodes := make([]map[string]any, 0)
		for _, node := range asObjectList(obj["nodes"]) {
			nodes = append(nodes, projectTask(node))
		}
		return map[string]any{"nodes": nodes, "edges": edges}
	case protocol.OpSessionsOpen, protocol.OpSessionsClose:
		session := obj
		if nested, ok := obj["session"].(map[string]any); ok {
			session = nested
		}
		return map[string]any{"session": projectSession(session)}
	case protocol.OpSessionsIO:
		session := obj
		if nested, ok := obj["session"].(map[string]any); ok {
			session = nested
		}
		out := map[string]any{"session": projectSession(session), "truncated": obj["truncated"] == true}
		if obj["cursor"] != nil {
			out["cursor"] = obj["cursor"]
		}
		return out
	default:
		return obj
	}
}

func proxyFileMutation(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient, op protocol.Operation) {
	body, err := decodeObject(r)
	if err != nil {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return
	}
	body["workspaceId"] = r.PathValue("workspaceId")
	proxyDashboard(w, r, runner, op, body)
}

func proxyWorkspace(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient, op protocol.Operation, extra map[string]any) {
	input := map[string]any{"workspaceId": r.PathValue("workspaceId")}
	for k, v := range extra {
		input[k] = v
	}
	proxyDashboard(w, r, runner, op, input)
}

func proxyWorkspaceMutation(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient, op protocol.Operation, extra map[string]any) {
	body, ok := decodeMutation(w, r)
	if !ok {
		return
	}
	body["workspaceId"] = r.PathValue("workspaceId")
	for k, v := range extra {
		body[k] = v
	}
	proxyDashboard(w, r, runner, op, body)
}

func decodeObject(r *http.Request) (map[string]any, error) {
	if r.Body == nil {
		return map[string]any{}, nil
	}
	var obj map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 12<<20)).Decode(&obj); err != nil {
		if err == io.EOF {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if obj == nil {
		obj = map[string]any{}
	}
	return obj, nil
}

func pageQuery(r *http.Request) map[string]any {
	input := map[string]any{}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		input["cursor"] = cursor
	}
	if limit := queryInt(r, "limit"); limit > 0 {
		input["limit"] = limit
	}
	return input
}

func queryInt(r *http.Request, name string) int {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}

func projectWorkspaceList(raw any) []map[string]any {
	switch rows := raw.(type) {
	case []map[string]any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, projectWorkspace(row))
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			obj, _ := row.(map[string]any)
			out = append(out, projectWorkspace(obj))
		}
		return out
	default:
		return []map[string]any{}
	}
}

func projectWorkspace(obj map[string]any) map[string]any {
	if obj == nil {
		return map[string]any{}
	}
	out := pickKeys(obj, "workspaceId", "repositoryUrl", "ref", "status", "networkProfile", "createdAt", "lastActivityAt", "expiresAt", "canRenewLease", "leaseState")
	if gen, ok := asInt(obj["generation"]); ok {
		out["version"] = gen
	}
	if actions, ok := stringSlice(obj["availableActions"]); ok {
		if len(actions) > 16 {
			actions = actions[:16]
		}
		out["availableActions"] = actions
	}
	if status, _ := obj["status"].(string); status == "FAILED" {
		out["error"] = "Workspace setup failed. Review runner logs."
	}
	return out
}

func projectFilesList(obj map[string]any) map[string]any {
	entries := []map[string]any{}
	switch rows := obj["entries"].(type) {
	case []map[string]any:
		for _, row := range rows {
			entries = append(entries, pickKeys(row, "name", "type"))
		}
	case []any:
		for _, row := range rows {
			item, _ := row.(map[string]any)
			entries = append(entries, pickKeys(item, "name", "type"))
		}
	}
	return map[string]any{"path": obj["path"], "entries": entries}
}

func pickKeys(obj map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	if obj == nil {
		return out
	}
	for _, k := range keys {
		if v, ok := obj[k]; ok {
			out[k] = v
		}
	}
	return out
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

func stringSlice(v any) ([]string, bool) {
	switch rows := v.(type) {
	case []string:
		return rows, true
	case []any:
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			s, ok := row.(string)
			if !ok {
				continue
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func projectGrantList(raw any) []map[string]any {
	switch rows := raw.(type) {
	case []map[string]any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, pickGrant(row))
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, pickGrant(row))
		}
		return out
	default:
		return []map[string]any{}
	}
}

func pickGrant(raw any) map[string]any {
	obj, _ := raw.(map[string]any)
	if obj == nil {
		return map[string]any{}
	}
	keys := []string{"id", "ownerId", "workspaceId", "command", "cwd", "commandSha256", "status", "createdAt", "expiresAt", "consumedAt"}
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := obj[k]; ok {
			out[k] = v
		}
	}
	return out
}

func writeDashboardFail(w http.ResponseWriter, result protocol.ToolResult) {
	code := protocol.ErrorInternal
	if result.Error != nil && result.Error.Code != "" {
		code = result.Error.Code
	}
	status := http.StatusInternalServerError
	switch code {
	case protocol.ErrorAuthenticationFailed:
		status = http.StatusUnauthorized
	case protocol.ErrorForbidden, protocol.ErrorNotFound:
		status = http.StatusNotFound
	case protocol.ErrorInvalidInput:
		status = http.StatusBadRequest
	case protocol.ErrorConflict:
		status = http.StatusConflict
	case protocol.ErrorExpired:
		status = http.StatusGone
	case protocol.ErrorLimitExceeded:
		status = http.StatusTooManyRequests
	case protocol.ErrorTimeout:
		status = http.StatusGatewayTimeout
	case protocol.ErrorUnavailable, protocol.ErrorDependencyEgressUnavailable:
		status = http.StatusServiceUnavailable
	}
	message := dashboardMessage(code)
	writeJSON(w, status, map[string]any{"error": strings.ToLower(string(code)), "message": message})
}

func dashboardMessage(code protocol.ErrorCode) string {
	switch code {
	case protocol.ErrorAuthenticationFailed:
		return "Your dashboard session ended."
	case protocol.ErrorForbidden, protocol.ErrorNotFound:
		return "Workspace not found or no longer available."
	case protocol.ErrorInvalidInput:
		return "The request could not be processed."
	case protocol.ErrorConflict:
		return "This item changed after you opened it."
	case protocol.ErrorExpired:
		return "Workspace expired."
	case protocol.ErrorLimitExceeded:
		return "Too many requests. Try again later."
	case protocol.ErrorTimeout:
		return "The workspace service took too long to respond."
	case protocol.ErrorUnavailable, protocol.ErrorDependencyEgressUnavailable:
		return "The workspace service is temporarily unavailable."
	default:
		return "The workspace service could not complete the request."
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
