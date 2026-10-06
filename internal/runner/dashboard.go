package runner

import (
	"context"
	"encoding/json"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func (s *Service) dashboard(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	ownerID := req.OwnerID
	if ownerID == "" {
		return protocol.Fail(protocol.ErrorAuthenticationFailed, "authentication failed", false)
	}
	switch req.Operation {
	case protocol.OpWorkspaceDetail:
		return s.workspaceDetail(req)
	case protocol.OpWorkspaceCloseFenced:
		return s.closeFenced(ctx, req)
	case protocol.OpMCPServerList, protocol.OpMCPServerGet, protocol.OpMCPServerUpdate, protocol.OpMCPServerDelete, protocol.OpMCPServerSetEnabled:
		return s.mcpGateway(req)
	case protocol.OpKnowledgeDashboardList, protocol.OpKnowledgeDashboardGet, protocol.OpKnowledgeDashboardCreate,
		protocol.OpKnowledgeDashboardUpdate, protocol.OpKnowledgeDashboardDelete, protocol.OpKnowledgeDashboardSearch,
		protocol.OpKnowledgeDashboardGraph, protocol.OpKnowledgeDashboardLinkCreate, protocol.OpKnowledgeDashboardLinkDelete:
		return s.knowledgeDashboard(req)
	case protocol.OpArtifactList:
		return s.artifactsList(req)
	case protocol.OpArtifactSnapshot:
		return s.artifactsSnapshot(req)
	case protocol.OpArtifactRead:
		return s.artifactsRead(req)
	case protocol.OpArtifactRestore:
		return s.artifactsRestore(ctx, req)
	case protocol.OpArtifactDelete:
		return s.artifactsDelete(req)
	case protocol.OpAuditList:
		return s.auditList(req)
	case protocol.OpGitHubStatus, protocol.OpGitHubSetupBegin, protocol.OpGitHubSetupComplete, protocol.OpGitHubReconcile, protocol.OpGitHubDisconnect:
		return s.githubDashboard(req)
	case protocol.OpProjectList, protocol.OpProjectCreate, protocol.OpProjectUpdate, protocol.OpProjectDelete,
		protocol.OpEnvironmentList, protocol.OpEnvironmentCreate, protocol.OpEnvironmentUpdate, protocol.OpEnvironmentDelete,
		protocol.OpSecretList, protocol.OpSecretCreate, protocol.OpSecretRotate, protocol.OpSecretUpdate, protocol.OpSecretDelete, protocol.OpSecretBulkApply,
		protocol.OpGlobalSecretList, protocol.OpGlobalSecretCreate, protocol.OpGlobalSecretRotate, protocol.OpGlobalSecretUpdate, protocol.OpGlobalSecretDelete, protocol.OpGlobalSecretBulkApply:
		return s.projectsDashboard(req)
	case protocol.OpPrivilegeGrantList:
		if s.grants == nil {
			return protocol.Fail(protocol.ErrorUnavailable, "privilege grant store is unavailable", true)
		}
		var input struct {
			WorkspaceID string `json:"workspaceId"`
		}
		if len(req.Input) > 0 {
			if err := json.Unmarshal(req.Input, &input); err != nil {
				return protocol.Fail(protocol.ErrorInvalidInput, "invalid privilege_grant_list input", false)
			}
		}
		rows := s.grants.List(ownerID, input.WorkspaceID, 50)
		out := make([]map[string]any, 0, len(rows))
		for _, g := range rows {
			out = append(out, g.PublicJSON())
		}
		return protocol.Success("Privilege grants listed", map[string]any{"grants": out})
	case protocol.OpPrivilegeGrantApprove:
		if s.grants == nil {
			return protocol.Fail(protocol.ErrorUnavailable, "privilege grant store is unavailable", true)
		}
		grantID := grantIDFrom(req.Input)
		if grantID == "" {
			return protocol.Fail(protocol.ErrorInvalidInput, "grantId is required", false)
		}
		if !s.grants.Approve(ownerID, grantID) {
			return protocol.Fail(protocol.ErrorNotFound, "privilege grant not found, expired, or already approved/consumed", false)
		}
		g, ok := s.grants.Get(grantID)
		if !ok || g.OwnerID != ownerID {
			return protocol.Fail(protocol.ErrorNotFound, "privilege grant not found, expired, or already approved/consumed", false)
		}
		return protocol.Success("Privilege grant approved", map[string]any{"grant": g.PublicJSON()})
	case protocol.OpPrivilegeGrantReject:
		if s.grants == nil {
			return protocol.Fail(protocol.ErrorUnavailable, "privilege grant store is unavailable", true)
		}
		grantID := grantIDFrom(req.Input)
		if grantID == "" {
			return protocol.Fail(protocol.ErrorInvalidInput, "grantId is required", false)
		}
		if !s.grants.Reject(ownerID, grantID) {
			return protocol.Fail(protocol.ErrorNotFound, "privilege grant not found or not in pending state", false)
		}
		g, ok := s.grants.Get(grantID)
		if !ok || g.OwnerID != ownerID {
			return protocol.Fail(protocol.ErrorNotFound, "privilege grant not found or not in pending state", false)
		}
		return protocol.Success("Privilege grant rejected", map[string]any{"grant": g.PublicJSON()})
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

func (s *Service) auditList(req protocol.RunnerRequest) protocol.ToolResult {
	if s.audit == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "audit store is unavailable", true)
	}
	var input struct {
		Cursor string `json:"cursor"`
		Limit  int    `json:"limit"`
	}
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid audit_list input", false)
		}
	}
	if input.Cursor != "" && !protocol.ValidOpaqueID(protocol.PrefixAudit, input.Cursor) {
		return protocol.Fail(protocol.ErrorInvalidInput, "cursor is invalid", false)
	}
	if input.Limit < 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "limit is invalid", false)
	}
	rows, err := s.audit.List(req.OwnerID, input.Cursor, input.Limit)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, e := range rows {
		out = append(out, e.PublicJSON())
	}
	res := protocol.Success("Audit events listed", map[string]any{"events": out})
	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if len(rows) == limit && limit > 0 {
		res.Cursor = rows[len(rows)-1].ID
	}
	return res
}

func grantIDFrom(raw json.RawMessage) string {
	var input struct {
		GrantID string `json:"grantId"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return ""
	}
	return input.GrantID
}
