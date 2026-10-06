package runner

import (
	"encoding/json"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func (s *Service) toolkitRegistryDashboard(req protocol.RunnerRequest) protocol.ToolResult {
	if s.skills == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "The toolkit registry is temporarily unavailable", true)
	}
	switch req.Operation {
	case protocol.OpToolkitRegistryList:
		var input struct {
			Provider string `json:"provider"`
		}
		_ = json.Unmarshal(req.Input, &input)
		if input.Provider != "" && input.Provider != "skills-sh" && input.Provider != "skillx" {
			return protocol.Fail(protocol.ErrorInvalidInput, "provider must be skills-sh or skillx", false)
		}
		entries, err := s.skills.ListRegistry(req.OwnerID, input.Provider)
		if err != nil {
			return skillFail(err)
		}
		presets := make([]map[string]any, 0, len(toolkitCatalog))
		for _, preset := range toolkitCatalog {
			presets = append(presets, map[string]any{
				"id": preset["id"], "name": preset["name"], "description": preset["description"],
				"sourceUrl": preset["sourceUrl"], "license": preset["license"],
				"defaultRevision": preset["defaultRevision"], "supportedScopes": preset["supportedScopes"],
				"installable": true,
			})
		}
		return protocol.Success("Registry catalog listed", map[string]any{"entries": entries, "presets": presets})
	case protocol.OpToolkitRegistryUpdate:
		var input struct {
			Provider           string `json:"provider"`
			Slug               string `json:"slug"`
			Action             string `json:"action"`
			RevisionID         string `json:"revisionId"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid toolkit_registry_update input", false)
		}
		switch input.Action {
		case "install", "pin", "enable", "disable":
		default:
			return protocol.Fail(protocol.ErrorInvalidInput, "action must be install, pin, enable, or disable", false)
		}
		meta := map[string]any{"action": input.Action}
		if input.RevisionID != "" {
			meta["revisionId"] = input.RevisionID
		}
		raw, _ := json.Marshal(meta)
		if err := s.skills.UpsertCatalogEntry(req.OwnerID, input.Provider, input.Slug, input.Slug, "", string(raw), time.Now().UnixMilli()); err != nil {
			return skillFail(err)
		}
		out := map[string]any{"provider": input.Provider, "slug": input.Slug, "action": input.Action}
		if input.RevisionID != "" {
			out["revisionId"] = input.RevisionID
		}
		return protocol.Success("Registry entry updated", out)
	case protocol.OpToolkitRegistryRefresh:
		var input struct {
			Provider string `json:"provider"`
		}
		_ = json.Unmarshal(req.Input, &input)
		if input.Provider != "" && input.Provider != "skills-sh" && input.Provider != "skillx" {
			return protocol.Fail(protocol.ErrorInvalidInput, "provider must be skills-sh or skillx", false)
		}
		rows, err := s.skills.ListCatalogEntries(req.OwnerID, input.Provider)
		if err != nil {
			return skillFail(err)
		}
		entries := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			entries = append(entries, row.PublicJSON())
		}
		return protocol.Success("Registry catalogue read", map[string]any{"entries": entries})
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}
