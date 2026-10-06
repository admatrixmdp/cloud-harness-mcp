package mcp

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/executor"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	localDefaultGitName  = "Cloud Harness Agent"
	localDefaultGitEmail = "agent@cloud-harness.local"
)

// LocalBackend executes confined file/search/exec tools against a host folder
// selected by `--workspace`. Remote-only operations stay unavailable.
type LocalBackend struct {
	Root       string
	GitNetwork bool
	GitPush    bool

	mu             sync.Mutex
	workspaceID    string
	status         string
	createdAt      time.Time
	lastActivityAt time.Time
	gitName        string
	gitEmail       string
	gitSource      string
}

// NewLocalBackend constructs a stdio workspace backend for an already-selected
// host folder. The synthetic workspace id is stable for the process lifetime.
func NewLocalBackend(root string, gitNetwork, gitPush bool) *LocalBackend {
	now := time.Now().UTC()
	return &LocalBackend{
		Root:           root,
		GitNetwork:     gitNetwork,
		GitPush:        gitPush,
		workspaceID:    protocol.NewOpaqueID("ws_local"),
		status:         "ACTIVE",
		createdAt:      now,
		lastActivityAt: now,
		gitName:        localDefaultGitName,
		gitEmail:       localDefaultGitEmail,
		gitSource:      "default",
	}
}

type localInput struct {
	WorkspaceID string `json:"workspaceId"`
	Mode        string `json:"mode"`
	Name        string `json:"name"`
	Email       string `json:"email"`
}

func (b *LocalBackend) parseInput(input json.RawMessage) (localInput, protocol.ToolResult, bool) {
	var parsed localInput
	if len(input) > 0 {
		if err := json.Unmarshal(input, &parsed); err != nil {
			return parsed, protocol.Fail(protocol.ErrorInvalidInput, "invalid local stdio input", false), false
		}
	}
	return parsed, protocol.ToolResult{}, true
}

func (b *LocalBackend) touch() {
	b.lastActivityAt = time.Now().UTC()
}

func (b *LocalBackend) requireID(workspaceID string) *protocol.ToolResult {
	if workspaceID != "" && workspaceID != b.workspaceID {
		fail := protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
		return &fail
	}
	return nil
}

func (b *LocalBackend) publicRecord() map[string]any {
	actions := []string{}
	leaseState := "EXPIRED"
	if b.status == "ACTIVE" {
		actions = []string{"workspace_lease_renew", "workspace_recover", "workspace_close", "workspace_context", "workspace_finalize"}
		leaseState = "ACTIVE"
	}
	return map[string]any{
		"workspaceId":      b.workspaceID,
		"repositoryUrl":    "local://" + b.Root,
		"ref":              "HEAD",
		"status":           b.status,
		"networkProfile":   string(protocol.ExposureLocalHost),
		"createdAt":        b.createdAt.Format(time.RFC3339Nano),
		"lastActivityAt":   b.lastActivityAt.Format(time.RFC3339Nano),
		"expiresAt":        time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339Nano),
		"leaseState":       leaseState,
		"canRenewLease":    false,
		"availableActions": actions,
	}
}

func (b *LocalBackend) capabilities() map[string]any {
	return map[string]any{
		"workspaceId":   b.workspaceID,
		"repository":    "local://" + b.Root,
		"repositoryUrl": "local://" + b.Root,
		"capabilities":  b.capabilityBlock(),
		"permissions":   b.permissions(),
		"operations":    b.operations(),
	}
}

func (b *LocalBackend) capabilityBlock() map[string]any {
	return map[string]any{
		"repository": map[string]any{
			"read":              true,
			"push":              b.GitPush,
			"issuesRead":        false,
			"issuesWrite":       false,
			"pullRequestsRead":  false,
			"pullRequestsWrite": false,
		},
		"workspace": map[string]any{
			"mode":                  "local",
			"platform":              runtime.GOOS,
			"gitNetwork":            b.GitNetwork,
			"gitPush":               b.GitPush,
			"sandboxed":             false,
			"shell":                 true,
			"tasks":                 true,
			"sessions":              true,
			"deployments":           true,
			"privileged":            false,
			"networkProfile":        string(protocol.ExposureLocalHost),
			"defaultNetworkProfile": string(protocol.ExposureLocalHost),
		},
		"mode":       "local",
		"platform":   runtime.GOOS,
		"gitNetwork": b.GitNetwork,
		"gitPush":    b.GitPush,
		"sandboxed":  false,
	}
}

func (b *LocalBackend) permissions() map[string]any {
	return map[string]any{
		"contents":     map[string]any{"read": true, "write": true},
		"issues":       map[string]any{"read": false, "write": false},
		"pullRequests": map[string]any{"read": false, "write": false},
	}
}

func (b *LocalBackend) operations() map[string]any {
	return map[string]any{
		"gitFetch":          b.GitNetwork,
		"gitPull":           b.GitNetwork,
		"gitPush":           b.GitPush,
		"issueList":         false,
		"issueView":         false,
		"issueCreate":       false,
		"issueComment":      false,
		"issueUpdate":       false,
		"issuePublish":      false,
		"labelCreate":       false,
		"pullRequestList":   false,
		"pullRequestView":   false,
		"pullRequestCreate": false,
		"commitList":        false,
		"compare":           false,
		"releaseList":       false,
		"tagList":           false,
		"execRun":           true,
		"privilegedExec":    false,
		"deploymentsRun":    true,
	}
}

func (b *LocalBackend) gitIdentity() map[string]any {
	return map[string]any{
		"name":   b.gitName,
		"email":  b.gitEmail,
		"source": b.gitSource,
	}
}

// Call implements Dispatcher.
func (b *LocalBackend) Call(ctx context.Context, op protocol.Operation, input json.RawMessage) protocol.ToolResult {
	parsed, fail, ok := b.parseInput(input)
	if !ok {
		return fail
	}

	switch op {
	case protocol.OpWorkspaceOpen:
		return protocol.Fail(protocol.ErrorInvalidInput, "workspace_open is unsupported in local stdio mode because the workspace is selected at startup via --workspace", false)
	case protocol.OpWorkspaceSetActive, protocol.OpWorkspaceFinalize:
		return protocol.Fail(protocol.ErrorInvalidInput, string(op)+" is unsupported in local stdio mode because the workspace is selected at startup via --workspace", false)
	case protocol.OpWorkspaceList:
		return b.workspaceList()
	case protocol.OpWorkspaceStatus:
		return b.workspaceStatus(parsed)
	case protocol.OpWorkspaceCapabilities:
		return b.workspaceCapabilities(parsed)
	case protocol.OpWorkspaceLeaseRenew:
		return b.workspaceLeaseRenew(parsed)
	case protocol.OpWorkspaceClose:
		return b.workspaceClose(parsed)
	case protocol.OpWorkspaceRecover:
		return b.workspaceRecover(ctx, parsed, input)
	case protocol.OpWorkspaceContext:
		return b.workspaceContext(parsed)
	case protocol.OpGitIdentityStatus:
		return b.gitIdentityStatus(parsed)
	case protocol.OpGitIdentitySet:
		return b.gitIdentitySet(parsed)
	case protocol.OpGitHubAction, protocol.OpGitHubRead:
		return protocol.Fail(protocol.ErrorRepositoryOperationNotAuthorized, string(op)+" is unsupported in local mode", false)
	case protocol.OpSecretsList:
		return protocol.Fail(protocol.ErrorInvalidInput, "secrets_list is unsupported in local stdio mode because retained environment secrets require remote runner storage", false)
	case protocol.OpArtifactsSnapshot, protocol.OpArtifactsList, protocol.OpArtifactsRead, protocol.OpArtifactsRestore, protocol.OpArtifactsDelete:
		return protocol.Fail(protocol.ErrorInvalidInput, string(op)+" is unsupported in local stdio mode because retained artifacts require remote runner storage", false)
	case protocol.OpKnowledgeCreate, protocol.OpKnowledgeRead, protocol.OpKnowledgeUpdate, protocol.OpKnowledgeDelete, protocol.OpKnowledgeList, protocol.OpKnowledgeSearch, protocol.OpKnowledgeLink, protocol.OpKnowledgeUnlink, protocol.OpKnowledgeGraph:
		return protocol.Fail(protocol.ErrorInvalidInput, string(op)+" is unsupported in local stdio mode because retained knowledge requires remote runner storage", false)
	case protocol.OpHooksActivate, protocol.OpHooksDeactivate:
		return protocol.Fail(protocol.ErrorInvalidInput, string(op)+" is unsupported in local stdio mode because retained hook activations require remote runner storage", false)
	case protocol.OpAgentSpawn, protocol.OpAgentStatus, protocol.OpAgentLogs, protocol.OpAgentMessage, protocol.OpAgentCancel, protocol.OpAgentList:
		return protocol.Fail(protocol.ErrorInvalidInput, string(op)+" is unsupported in local stdio mode because coding agents require the remote runner and model gateway", false)
	case protocol.OpGitFetch, protocol.OpGitPull, protocol.OpGitPush:
		if op == protocol.OpGitPush && !b.GitPush {
			return protocol.Fail(protocol.ErrorRepositoryOperationNotAuthorized, "Git push operations are disabled in local mode; pass --git-push to enable", false)
		}
		if !b.GitNetwork {
			return protocol.Fail(protocol.ErrorForbidden, "network Git operations are disabled in local mode; pass --git-network to enable", false)
		}
		return (executor.Workspace{Root: b.Root}).Execute(ctx, op, input)
	case protocol.OpFilesList, protocol.OpFilesRead, protocol.OpFilesWrite, protocol.OpFilesDelete, protocol.OpFilesMkdir, protocol.OpFilesApplyPatch, protocol.OpFilesWriteBatch, protocol.OpFilesMove, protocol.OpGrepSearch, protocol.OpSymbolsSearch, protocol.OpSymbolsReferences, protocol.OpExecRun, protocol.OpGitStatus, protocol.OpGitDiff, protocol.OpGitLog, protocol.OpGitBranch, protocol.OpGitCheckout, protocol.OpGitAdd, protocol.OpGitCommit, protocol.OpGitMerge, protocol.OpGitRebase, protocol.OpWorktreesList, protocol.OpWorktreesCreate, protocol.OpWorktreesRemove, protocol.OpSkillsList, protocol.OpSkillsRead, protocol.OpSkillsRun, protocol.OpSkillSuggest, protocol.OpSessionsList, protocol.OpSessionsOpen, protocol.OpSessionsIO, protocol.OpSessionsClose, protocol.OpShellOpen, protocol.OpShellIO, protocol.OpShellClose, protocol.OpTasksList, protocol.OpTasksRun, protocol.OpTasksStatus, protocol.OpTasksCancel, protocol.OpTasksGraph, protocol.OpOperationStatus, protocol.OpOperationCancel, protocol.OpOperationWait, protocol.OpHooksList, protocol.OpHooksRun, protocol.OpDeploymentsList, protocol.OpDeploymentsRun, protocol.OpMemoriesList, protocol.OpMemoriesRead, protocol.OpMemoriesWrite, protocol.OpMemoriesSearch, protocol.OpMemoriesDelete:
		return (executor.Workspace{Root: b.Root}).Execute(ctx, op, input)
	default:
		return protocol.Fail(protocol.ErrorUnavailable, "Go-port stdio has not implemented "+string(op)+" yet", true)
	}
}

func (b *LocalBackend) workspaceList() protocol.ToolResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.touch()
	if b.status == "CLOSED" {
		return protocol.Success("Listed 0 workspaces", map[string]any{"workspaces": []any{}})
	}
	return protocol.Success("Listed 1 workspace", map[string]any{"workspaces": []any{b.publicRecord()}})
}

func (b *LocalBackend) workspaceStatus(in localInput) protocol.ToolResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if errRes := b.requireID(in.WorkspaceID); errRes != nil {
		return *errRes
	}
	if b.status == "CLOSED" {
		return protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
	}
	b.touch()
	data := b.publicRecord()
	caps := b.capabilities()
	data["root"] = b.Root
	data["capabilities"] = caps["capabilities"]
	data["permissions"] = caps["permissions"]
	data["operations"] = caps["operations"]
	return protocol.Success("Workspace status retrieved", data)
}

func (b *LocalBackend) workspaceCapabilities(in localInput) protocol.ToolResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if errRes := b.requireID(in.WorkspaceID); errRes != nil {
		return *errRes
	}
	b.touch()
	return protocol.Success("Workspace capabilities retrieved", b.capabilities())
}

func (b *LocalBackend) workspaceLeaseRenew(in localInput) protocol.ToolResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if errRes := b.requireID(in.WorkspaceID); errRes != nil {
		return *errRes
	}
	if b.status == "CLOSED" {
		return protocol.Fail(protocol.ErrorExpired, "workspace is closed and cannot be renewed", false)
	}
	b.touch()
	return protocol.Success("Local workspace lease is permanent", b.publicRecord())
}

func (b *LocalBackend) workspaceClose(in localInput) protocol.ToolResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if in.WorkspaceID != b.workspaceID {
		return protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
	}
	b.status = "CLOSED"
	b.touch()
	return protocol.Success("Workspace closed", map[string]any{
		"workspaceId": b.workspaceID,
		"status":      "CLOSED",
	})
}

func (b *LocalBackend) workspaceRecover(ctx context.Context, in localInput, input json.RawMessage) protocol.ToolResult {
	b.mu.Lock()
	if errRes := b.requireID(in.WorkspaceID); errRes != nil {
		b.mu.Unlock()
		return *errRes
	}
	if b.status == "CLOSED" {
		b.mu.Unlock()
		return protocol.Fail(protocol.ErrorExpired, "workspace is closed and cannot be recovered", false)
	}
	b.touch()
	mode := in.Mode
	if mode == "" {
		mode = "resume"
	}
	if mode == "resume" {
		rec := b.publicRecord()
		b.mu.Unlock()
		return protocol.Success("Local workspace is already active", rec)
	}
	b.mu.Unlock()
	got := (executor.Workspace{Root: b.Root}).Execute(ctx, protocol.OpWorkspaceRecover, input)
	if !got.OK {
		return got
	}
	data := map[string]any{"workspaceRoot": b.Root}
	if extra, ok := got.Data.(map[string]any); ok {
		for k, v := range extra {
			data[k] = v
		}
	}
	return protocol.Success(got.Message, data)
}

func (b *LocalBackend) workspaceContext(in localInput) protocol.ToolResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if errRes := b.requireID(in.WorkspaceID); errRes != nil {
		return *errRes
	}
	if b.status == "CLOSED" {
		return protocol.Fail(protocol.ErrorNotFound, "workspace is closed", false)
	}
	b.touch()
	caps := b.capabilities()
	rec := b.publicRecord()
	rec["root"] = b.Root
	rec["capabilities"] = caps["capabilities"]
	rec["permissions"] = caps["permissions"]
	rec["operations"] = caps["operations"]
	return protocol.Success("Workspace context", map[string]any{
		"workspace":        rec,
		"branch":           "HEAD",
		"gitIdentity":      b.gitIdentity(),
		"capabilities":     caps["capabilities"],
		"permissions":      caps["permissions"],
		"operations":       caps["operations"],
		"status":           "ACTIVE",
		"workspaceRoot":    b.Root,
		"availableActions": rec["availableActions"],
	})
}

func (b *LocalBackend) gitIdentityStatus(in localInput) protocol.ToolResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if errRes := b.requireID(in.WorkspaceID); errRes != nil {
		return *errRes
	}
	if b.status == "CLOSED" {
		return protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
	}
	b.touch()
	return protocol.Success("Git identity status", b.gitIdentity())
}

func (b *LocalBackend) gitIdentitySet(in localInput) protocol.ToolResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if errRes := b.requireID(in.WorkspaceID); errRes != nil {
		return *errRes
	}
	if b.status == "CLOSED" {
		return protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(in.Name) > 200 {
		return protocol.Fail(protocol.ErrorInvalidInput, "name is required", false)
	}
	if !strings.Contains(in.Email, "@") || strings.ContainsAny(in.Email, " \n") {
		return protocol.Fail(protocol.ErrorInvalidInput, "email is required", false)
	}
	b.gitName = name
	b.gitEmail = in.Email
	b.gitSource = "owner"
	b.touch()
	return protocol.Success("Git identity configured", map[string]any{"name": name, "email": in.Email})
}
