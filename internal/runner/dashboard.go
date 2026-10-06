package runner

import (
	"encoding/json"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func (s *Service) dashboard(req protocol.RunnerRequest) protocol.ToolResult {
	if s.grants == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "privilege grant store is unavailable", true)
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		return protocol.Fail(protocol.ErrorAuthenticationFailed, "authentication failed", false)
	}
	switch req.Operation {
	case protocol.OpPrivilegeGrantList:
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

func grantIDFrom(raw json.RawMessage) string {
	var input struct {
		GrantID string `json:"grantId"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return ""
	}
	return input.GrantID
}
