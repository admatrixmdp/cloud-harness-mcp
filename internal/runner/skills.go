package runner

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/skillarchive"
	"github.com/bestagentkits/cloud-harness-mcp/internal/skillsreg"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func (s *Service) skillsDashboard(req protocol.RunnerRequest) protocol.ToolResult {
	if s.skills == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "The skill registry is temporarily unavailable", true)
	}
	now := time.Now().UnixMilli()
	switch req.Operation {
	case protocol.OpSkillList:
		var input struct {
			State    string `json:"state"`
			Kind     string `json:"kind"`
			Provider string `json:"provider"`
			Limit    int    `json:"limit"`
		}
		_ = json.Unmarshal(req.Input, &input)
		rows, err := s.skills.List(req.OwnerID, input.State, input.Kind, input.Provider, input.Limit)
		if err != nil {
			return skillFail(err)
		}
		return protocol.Success("Skills listed", map[string]any{"skills": sourcesJSON(rows)})
	case protocol.OpSkillGet:
		id, errRes := requireSkillID(req.Input)
		if errRes != nil {
			return *errRes
		}
		row, err := s.skills.Get(req.OwnerID, id)
		if err != nil {
			return skillFail(err)
		}
		return protocol.Success("Skill read", row.PublicJSON())
	case protocol.OpSkillCreateCustom:
		var input struct {
			Slug                string   `json:"slug"`
			DisplayName         string   `json:"displayName"`
			Description         string   `json:"description"`
			Tags                []string `json:"tags"`
			Instructions        string   `json:"instructions"`
			HasExecutableAssets bool     `json:"hasExecutableAssets"`
			Version             string   `json:"version"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_create_custom input", false)
		}
		row, err := s.skills.CreateCustom(req.OwnerID, input.Slug, input.DisplayName, input.Description, input.Instructions, input.Tags, input.HasExecutableAssets, input.Version, now)
		return skillMutation("Custom skill created", row.PublicJSON(), err)
	case protocol.OpSkillUpdate:
		var input struct {
			SkillID            string   `json:"skillId"`
			DisplayName        *string  `json:"displayName"`
			Description        *string  `json:"description"`
			Tags               []string `json:"tags"`
			ExpectedGeneration int      `json:"expectedGeneration"`
		}
		raw := map[string]any{}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_update input", false)
		}
		_ = json.Unmarshal(req.Input, &raw)
		_, tagsSet := raw["tags"]
		row, err := s.skills.UpdateMetadata(req.OwnerID, input.SkillID, input.ExpectedGeneration, input.DisplayName, input.Description, input.Tags, tagsSet, now)
		return skillMutation("Skill updated", row.PublicJSON(), err)
	case protocol.OpSkillArchive:
		id, gen, errRes := skillGenerationInput(req.Input, "skillId")
		if errRes != nil {
			return *errRes
		}
		row, err := s.skills.SetState(req.OwnerID, id, "archived", gen, now)
		return skillMutation("Skill archived", row.PublicJSON(), err)
	case protocol.OpSkillRestore:
		var input struct {
			SkillID            string `json:"skillId"`
			RevisionID         string `json:"revisionId"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_restore input", false)
		}
		row, err := s.skills.Restore(req.OwnerID, input.SkillID, input.RevisionID, input.ExpectedGeneration, now)
		return skillMutation("Skill restored", row.PublicJSON(), err)
	case protocol.OpSkillBulk:
		var input struct {
			Action             string   `json:"action"`
			SkillIDs           []string `json:"skillIds"`
			ExpectedGeneration int      `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_bulk input", false)
		}
		state := map[string]string{"enable": "enabled", "disable": "disabled", "archive": "archived"}[input.Action]
		if state == "" {
			return protocol.Fail(protocol.ErrorInvalidInput, "unsupported bulk action", false)
		}
		results := make([]map[string]any, 0, len(input.SkillIDs))
		for _, id := range input.SkillIDs {
			_, err := s.skills.SetState(req.OwnerID, id, state, input.ExpectedGeneration, now)
			if err != nil {
				code := "INTERNAL_ERROR"
				if errors.Is(err, skillsreg.ErrNotFound) {
					code = "NOT_FOUND"
				} else if errors.Is(err, skillsreg.ErrConflict) {
					code = "CONFLICT"
				} else if errors.Is(err, skillsreg.ErrInvalid) {
					code = "INVALID_INPUT"
				}
				results = append(results, map[string]any{"skillId": id, "ok": false, "error": code})
				continue
			}
			results = append(results, map[string]any{"skillId": id, "ok": true})
		}
		return protocol.Success("Skills updated in bulk", map[string]any{"results": results})
	case protocol.OpSkillUsage:
		id, errRes := requireSkillID(req.Input)
		if errRes != nil {
			return *errRes
		}
		data, err := s.skills.Usage(req.OwnerID, id)
		if err != nil {
			return skillFail(err)
		}
		return protocol.Success("Skill usage listed", data)
	case protocol.OpSkillSearch:
		var input struct {
			Query     string   `json:"query"`
			Providers []string `json:"providers"`
			Limit     int      `json:"limit"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_search input", false)
		}
		local, err := s.skills.SearchLocal(req.OwnerID, input.Query, input.Limit)
		if err != nil {
			return skillFail(err)
		}
		providers := []map[string]any{}
		for _, p := range input.Providers {
			if p == "local" || p == "" {
				continue
			}
			providers = append(providers, map[string]any{"provider": p, "status": "unavailable", "count": 0, "warning": "remote registry search is not configured"})
		}
		return protocol.Success("Skills searched", map[string]any{
			"local":     sourcesJSON(local),
			"providers": providers,
			"results":   []any{},
		})
	case protocol.OpSkillRevisionList:
		id, errRes := requireSkillID(req.Input)
		if errRes != nil {
			return *errRes
		}
		var input struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(req.Input, &input)
		rows, err := s.skills.ListRevisions(req.OwnerID, id, input.Limit)
		if err != nil {
			return skillFail(err)
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.PublicJSON())
		}
		return protocol.Success("Skill revisions listed", map[string]any{"revisions": out})
	case protocol.OpSkillRevisionGet:
		var input struct {
			SkillID    string `json:"skillId"`
			RevisionID string `json:"revisionId"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_revision_get input", false)
		}
		row, err := s.skills.GetRevision(req.OwnerID, input.SkillID, input.RevisionID)
		if err != nil {
			return skillFail(err)
		}
		return protocol.Success("Skill revision read", row.PublicJSON())
	case protocol.OpSkillRevisionDiff:
		var input struct {
			SkillID        string `json:"skillId"`
			FromRevisionID string `json:"fromRevisionId"`
			ToRevisionID   string `json:"toRevisionId"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_revision_diff input", false)
		}
		from, err := s.skills.GetRevision(req.OwnerID, input.SkillID, input.FromRevisionID)
		if err != nil {
			return skillFail(err)
		}
		to, err := s.skills.GetRevision(req.OwnerID, input.SkillID, input.ToRevisionID)
		if err != nil {
			return skillFail(err)
		}
		out := to.PublicJSON()
		out["diff"] = "content sha256 " + from.ContentSHA256 + " -> " + to.ContentSHA256
		return protocol.Success("Skill revision diff", out)
	case protocol.OpSkillRevisionCreate:
		var input struct {
			SkillID            string `json:"skillId"`
			Instructions       string `json:"instructions"`
			ExpectedGeneration int    `json:"expectedGeneration"`
			Version            string `json:"version"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_revision_create input", false)
		}
		id, err := s.skills.CreateEdit(req.OwnerID, input.SkillID, input.Instructions, input.Version, input.ExpectedGeneration, now)
		if err != nil {
			return skillFail(err)
		}
		return protocol.Success("Skill revision created", map[string]any{"sourceId": input.SkillID, "revisionId": id})
	case protocol.OpSkillRevisionFork:
		var input struct {
			SkillID     string `json:"skillId"`
			RevisionID  string `json:"revisionId"`
			Slug        string `json:"slug"`
			DisplayName string `json:"displayName"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_revision_fork input", false)
		}
		row, from, err := s.skills.Fork(req.OwnerID, input.SkillID, input.RevisionID, input.Slug, input.DisplayName, now)
		if err != nil {
			return skillFail(err)
		}
		data := row.PublicJSON()
		data["sourceId"] = row.ID
		data["revisionId"] = row.CurrentRevisionID
		data["forkedFrom"] = from
		return protocol.Success("Skill forked", data)
	case protocol.OpSkillImportStart:
		var input struct {
			SourceKind string `json:"sourceKind"`
			SourceRef  string `json:"sourceRef"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_import_start input", false)
		}
		job, err := s.skills.StartImport(req.OwnerID, input.SourceKind, input.SourceRef, now)
		return skillMutation("Skill import started", job.PublicJSON(), err)
	case protocol.OpSkillImportStatus:
		var input struct {
			JobID string `json:"jobId"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_import_status input", false)
		}
		job, err := s.skills.GetImport(req.OwnerID, input.JobID)
		if err != nil {
			return skillFail(err)
		}
		return protocol.Success("Import job read", job.PublicJSON())
	case protocol.OpSkillImportCancel:
		var input struct {
			JobID string `json:"jobId"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_import_cancel input", false)
		}
		job, err := s.skills.CancelImport(req.OwnerID, input.JobID, now)
		return skillMutation("Import job cancelled", job.PublicJSON(), err)
	case protocol.OpSkillSetList:
		var input struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(req.Input, &input)
		rows, err := s.skills.ListSets(req.OwnerID, input.Limit)
		if err != nil {
			return skillFail(err)
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.PublicJSON())
		}
		return protocol.Success("Skill sets listed", map[string]any{"sets": out})
	case protocol.OpSkillSetGet:
		var input struct {
			SkillSetID string `json:"skillSetId"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_set_get input", false)
		}
		row, err := s.skills.GetSet(req.OwnerID, input.SkillSetID)
		if err != nil {
			return skillFail(err)
		}
		return protocol.Success("Skill set read", row.PublicGetJSON())
	case protocol.OpSkillSetCreate:
		var input struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Items       []struct {
				SkillSourceID string `json:"skillSourceId"`
				RevisionID    string `json:"revisionId"`
				Name          string `json:"name"`
			} `json:"items"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_set_create input", false)
		}
		items := make([]skillsreg.SetItem, 0, len(input.Items))
		for _, item := range input.Items {
			items = append(items, skillsreg.SetItem{SkillSourceID: item.SkillSourceID, RevisionID: item.RevisionID, Name: item.Name})
		}
		row, err := s.skills.CreateSet(req.OwnerID, input.Name, input.Description, items, now)
		return skillMutation("Skill set created", row.PublicJSON(), err)
	case protocol.OpSkillSetUpdate:
		var raw map[string]any
		_ = json.Unmarshal(req.Input, &raw)
		var input struct {
			SkillSetID         string  `json:"skillSetId"`
			Name               *string `json:"name"`
			Description        *string `json:"description"`
			ExpectedGeneration int     `json:"expectedGeneration"`
			Items              []struct {
				SkillSourceID string `json:"skillSourceId"`
				RevisionID    string `json:"revisionId"`
				Name          string `json:"name"`
			} `json:"items"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_set_update input", false)
		}
		_, itemsSet := raw["items"]
		items := make([]skillsreg.SetItem, 0, len(input.Items))
		for _, item := range input.Items {
			items = append(items, skillsreg.SetItem{SkillSourceID: item.SkillSourceID, RevisionID: item.RevisionID, Name: item.Name})
		}
		row, err := s.skills.UpdateSet(req.OwnerID, input.SkillSetID, input.ExpectedGeneration, input.Name, input.Description, items, itemsSet, now)
		return skillMutation("Skill set updated", row.PublicJSON(), err)
	case protocol.OpSkillSetDelete:
		var input struct {
			SkillSetID         string `json:"skillSetId"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_set_delete input", false)
		}
		if err := s.skills.DeleteSet(req.OwnerID, input.SkillSetID, input.ExpectedGeneration); err != nil {
			return skillFail(err)
		}
		return protocol.Success("Skill set deleted", map[string]any{"id": input.SkillSetID, "deleted": true})
	case protocol.OpSkillSetPreview:
		var input struct {
			SkillSets []struct {
				SkillSetID         string `json:"skillSetId"`
				ExpectedGeneration int    `json:"expectedGeneration"`
			} `json:"skillSets"`
			SkillOverrides map[string]string `json:"skillOverrides"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_set_preview input", false)
		}
		requested := make([]skillsreg.PreviewRequest, 0, len(input.SkillSets))
		for _, item := range input.SkillSets {
			requested = append(requested, skillsreg.PreviewRequest{SkillSetID: item.SkillSetID, ExpectedGeneration: item.ExpectedGeneration})
		}
		data, err := s.skills.Preview(req.OwnerID, requested, input.SkillOverrides)
		if err != nil {
			return skillFail(err)
		}
		return protocol.Success("Skill set preview", data)
	case protocol.OpSkillArchiveImport:
		var input struct {
			ArchiveBase64      string `json:"archiveBase64"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_archive_import input", false)
		}
		if input.ExpectedGeneration != 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "expectedGeneration must be 0", false)
		}
		if input.ArchiveBase64 == "" || len(input.ArchiveBase64) > skillarchive.MaxBase64 {
			return protocol.Fail(protocol.ErrorInvalidInput, "the archive is larger than the limit", false)
		}
		raw, err := base64.StdEncoding.DecodeString(input.ArchiveBase64)
		if err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "the archive could not be decoded", false)
		}
		entries, err := skillarchive.Read(raw)
		if err != nil {
			return skillFail(err)
		}
		results := make([]map[string]any, 0, len(entries))
		for _, entry := range entries {
			row, err := s.skills.CreateCustom(req.OwnerID, entry.Slug, entry.DisplayName, "", entry.Instructions, nil, false, skillarchive.TrustedVersion(entry.Instructions), now)
			if err != nil {
				code := "INTERNAL_ERROR"
				if errors.Is(err, skillsreg.ErrConflict) {
					code = "CONFLICT"
				} else if errors.Is(err, skillsreg.ErrInvalid) {
					code = "INVALID_INPUT"
				}
				results = append(results, map[string]any{"slug": entry.Slug, "ok": false, "error": code})
				continue
			}
			results = append(results, map[string]any{"slug": entry.Slug, "ok": true, "skillId": row.ID})
		}
		return protocol.Success("Skills imported from the archive", map[string]any{"results": results})
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

func sourcesJSON(rows []skillsreg.Source) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.PublicJSON())
	}
	return out
}

func requireSkillID(raw json.RawMessage) (string, *protocol.ToolResult) {
	var input struct {
		SkillID string `json:"skillId"`
	}
	if err := json.Unmarshal(raw, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixSkillSource, input.SkillID) {
		res := protocol.Fail(protocol.ErrorInvalidInput, "skillId is invalid", false)
		return "", &res
	}
	return input.SkillID, nil
}

func skillGenerationInput(raw json.RawMessage, idField string) (string, int, *protocol.ToolResult) {
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		res := protocol.Fail(protocol.ErrorInvalidInput, "invalid input", false)
		return "", 0, &res
	}
	id, _ := input[idField].(string)
	gen := skillInt(input["expectedGeneration"])
	if id == "" {
		res := protocol.Fail(protocol.ErrorInvalidInput, idField+" is invalid", false)
		return "", 0, &res
	}
	return id, gen, nil
}

func skillInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

func skillMutation(message string, data map[string]any, err error) protocol.ToolResult {
	if err != nil {
		return skillFail(err)
	}
	return protocol.Success(message, data)
}

func skillFail(err error) protocol.ToolResult {
	if errors.Is(err, skillsreg.ErrNotFound) {
		return protocol.Fail(protocol.ErrorNotFound, err.Error(), false)
	}
	if errors.Is(err, skillsreg.ErrConflict) {
		return protocol.Fail(protocol.ErrorConflict, "This item changed after you opened it.", false)
	}
	if errors.Is(err, skillsreg.ErrInvalid) || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "unsupported") {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
}
