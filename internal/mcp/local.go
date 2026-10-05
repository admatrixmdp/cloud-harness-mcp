package mcp

import (
	"context"
	"encoding/json"

	"github.com/bestagentkits/cloud-harness-mcp/internal/executor"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// LocalBackend executes confined file/search/exec tools against a host folder
// selected by `--workspace`. Remote-only operations stay unavailable.
type LocalBackend struct {
	Root       string
	GitNetwork bool
	GitPush    bool
}

// Call implements Dispatcher.
func (b LocalBackend) Call(ctx context.Context, op protocol.Operation, input json.RawMessage) protocol.ToolResult {
	switch op {
	case protocol.OpWorkspaceOpen:
		return protocol.Fail(protocol.ErrorInvalidInput, "workspace_open is unsupported in local stdio mode because the workspace is selected at startup via --workspace", false)
	case protocol.OpWorkspaceClose, protocol.OpWorkspaceSetActive, protocol.OpWorkspaceFinalize:
		return protocol.Fail(protocol.ErrorInvalidInput, string(op)+" is unsupported in local stdio mode because the workspace is selected at startup via --workspace", false)
	case protocol.OpWorkspaceRecover:
		mode := "resume"
		if len(input) > 0 {
			var parsed struct {
				Mode string `json:"mode"`
			}
			_ = json.Unmarshal(input, &parsed)
			if parsed.Mode != "" {
				mode = parsed.Mode
			}
		}
		if mode != "resume" {
			return protocol.Fail(protocol.ErrorUnavailable, "local workspace_recover mode "+mode+" is not wired in this Go-port slice", true)
		}
		return protocol.Success("Local workspace is already active", map[string]any{"status": "ACTIVE"})
	case protocol.OpWorkspaceContext:
		return protocol.Success("workspace context", map[string]any{
			"status":           "ACTIVE",
			"workspaceRoot":    b.Root,
			"availableActions": []string{"workspace_context"},
		})
	case protocol.OpSecretsList, protocol.OpArtifactsSnapshot, protocol.OpArtifactsList, protocol.OpArtifactsRead, protocol.OpArtifactsRestore, protocol.OpArtifactsDelete:
		return protocol.Fail(protocol.ErrorInvalidInput, string(op)+" is unsupported in local stdio mode because retained artifacts require remote runner storage", false)
	case protocol.OpGitFetch, protocol.OpGitPull, protocol.OpGitPush:
		if op == protocol.OpGitPush && !b.GitPush {
			return protocol.Fail(protocol.ErrorForbidden, "git push requires --git-push", false)
		}
		if !b.GitNetwork {
			return protocol.Fail(protocol.ErrorForbidden, "git network operations require --git-network", false)
		}
		return protocol.Fail(protocol.ErrorUnavailable, "local git network operations are not wired in this Go-port slice", true)
	case protocol.OpFilesList, protocol.OpFilesRead, protocol.OpFilesWrite, protocol.OpFilesDelete, protocol.OpFilesMkdir, protocol.OpFilesApplyPatch, protocol.OpFilesWriteBatch, protocol.OpFilesMove, protocol.OpGrepSearch, protocol.OpSymbolsSearch, protocol.OpSymbolsReferences, protocol.OpExecRun, protocol.OpGitStatus, protocol.OpGitDiff, protocol.OpGitLog:
		return (executor.Workspace{Root: b.Root}).Execute(ctx, op, input)
	default:
		return protocol.Fail(protocol.ErrorUnavailable, "Go-port stdio has not implemented "+string(op)+" yet", true)
	}
}
