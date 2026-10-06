package runner

import (
	"encoding/json"
	"fmt"

	"github.com/bestagentkits/cloud-harness-mcp/internal/knowledge"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func (s *Service) knowledgeDashboard(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge dashboard input", false)
		}
	}
	switch req.Operation {
	case protocol.OpKnowledgeDashboardList:
		return s.knowledgeDashboardList(store, ownerID, input)
	case protocol.OpKnowledgeDashboardGet:
		item, err := store.Read(ownerID, input.ID)
		if err != nil {
			return knowledgeFail(err)
		}
		return protocol.Success("Knowledge item retrieved", item.PublicJSON())
	case protocol.OpKnowledgeDashboardCreate:
		expected := 0
		if input.ExpectedGeneration != nil {
			expected = *input.ExpectedGeneration
		}
		retention := 0
		if input.RetentionSeconds != nil {
			retention = *input.RetentionSeconds
		}
		occurred := int64(0)
		if input.OccurredAt != nil {
			occurred = *input.OccurredAt
		}
		item, err := store.Create(knowledge.CreateParams{
			PrincipalID: ownerID, Kind: input.Kind, Scope: input.Scope, ProjectID: input.ProjectID,
			WorkspaceID: input.WorkspaceID, Title: input.Title, Content: input.Content, JournalType: input.JournalType,
			OccurredAt: occurred, Tags: input.Tags, RetentionSeconds: retention, ExpectedGeneration: expected,
		})
		if err != nil {
			return knowledgeFail(err)
		}
		return protocol.Success("Knowledge item created", item.PublicJSON())
	case protocol.OpKnowledgeDashboardUpdate:
		var raw map[string]any
		_ = json.Unmarshal(req.Input, &raw)
		expected := 0
		if input.ExpectedGeneration != nil {
			expected = *input.ExpectedGeneration
		}
		p := knowledge.UpdateParams{PrincipalID: ownerID, ID: input.ID, ExpectedGeneration: expected}
		if _, ok := raw["title"]; ok {
			p.Title = &input.Title
		}
		if _, ok := raw["content"]; ok {
			p.Content = &input.Content
		}
		if _, ok := raw["journalType"]; ok {
			p.JournalType = &input.JournalType
		}
		if input.OccurredAt != nil {
			p.OccurredAt = input.OccurredAt
		}
		if _, ok := raw["tags"]; ok {
			p.Tags = &input.Tags
		}
		p.RetentionSeconds = input.RetentionSeconds
		item, err := store.Update(p)
		if err != nil {
			return knowledgeFail(err)
		}
		return protocol.Success("Knowledge item updated", item.PublicJSON())
	case protocol.OpKnowledgeDashboardDelete:
		expected := 0
		if input.ExpectedGeneration != nil {
			expected = *input.ExpectedGeneration
		}
		if err := store.Delete(ownerID, input.ID, expected); err != nil {
			return knowledgeFail(err)
		}
		return protocol.Success("Knowledge item deleted", map[string]any{"deleted": true})
	case protocol.OpKnowledgeDashboardSearch:
		return s.knowledgeDashboardSearch(store, ownerID, input)
	case protocol.OpKnowledgeDashboardGraph:
		depth := 1
		if input.Depth != nil {
			depth = *input.Depth
		}
		maxNodes := 50
		if input.MaxNodes != nil {
			maxNodes = *input.MaxNodes
		}
		nodes, edges, truncated, err := store.Graph(knowledge.GraphParams{
			PrincipalID: ownerID, RootID: input.RootID, Depth: depth, MaxNodes: maxNodes,
			Kinds: input.Kinds, ProjectID: input.ProjectID,
		})
		if err != nil {
			return knowledgeFail(err)
		}
		outNodes := make([]map[string]any, 0, len(nodes))
		for _, n := range nodes {
			outNodes = append(outNodes, n.PublicJSON())
		}
		outEdges := make([]map[string]any, 0, len(edges))
		for _, e := range edges {
			outEdges = append(outEdges, e.PublicJSON())
		}
		got := protocol.Success(fmt.Sprintf("Graph returned with %d nodes and %d edges", len(outNodes), len(outEdges)), map[string]any{
			"nodes": outNodes, "edges": outEdges, "truncated": truncated,
		})
		got.Truncated = truncated
		return got
	case protocol.OpKnowledgeDashboardLinkCreate:
		link, err := store.CreateLink(ownerID, input.SourceID, input.TargetID, input.Relation, "manual")
		if err != nil {
			return knowledgeFail(err)
		}
		return protocol.Success("Knowledge link created", link.PublicJSON())
	case protocol.OpKnowledgeDashboardLinkDelete:
		unlinked, err := store.DeleteLink(ownerID, input.LinkID, input.SourceID, input.TargetID, input.Relation)
		if err != nil {
			return knowledgeFail(err)
		}
		return protocol.Success("Knowledge link deleted", map[string]any{"unlinked": unlinked})
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown knowledge dashboard operation", false)
	}
}

func (s *Service) knowledgeDashboardList(store *knowledge.Store, ownerID string, input knowledgeInput) protocol.ToolResult {
	limit := 50
	if input.Limit != nil {
		limit = *input.Limit
	}
	rows, next, err := store.List(knowledge.ListParams{
		PrincipalID: ownerID, Kind: input.Kind, Scope: input.Scope, ProjectID: input.ProjectID,
		WorkspaceID: input.WorkspaceID, JournalType: input.JournalType, Tags: input.Tags, TagMatch: input.TagMatch,
		Limit: limit, Cursor: input.Cursor,
	})
	if err != nil {
		return knowledgeFail(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.PublicJSON())
	}
	got := protocol.Success(fmt.Sprintf("Found %d knowledge items", len(out)), map[string]any{"items": out})
	if next != "" {
		got.Cursor = next
		got.Truncated = true
		got.Data = map[string]any{"items": out, "cursor": next}
	}
	return got
}

func (s *Service) knowledgeDashboardSearch(store *knowledge.Store, ownerID string, input knowledgeInput) protocol.ToolResult {
	limit := 20
	if input.Limit != nil {
		limit = *input.Limit
	}
	hits, next, err := store.SearchHits(knowledge.ListParams{
		PrincipalID: ownerID, Kind: input.Kind, Scope: input.Scope, ProjectID: input.ProjectID,
		WorkspaceID: input.WorkspaceID, JournalType: input.JournalType, Tags: input.Tags, TagMatch: input.TagMatch,
		Query: input.Query, Kinds: input.Kinds, Limit: limit, Cursor: input.Cursor,
	})
	if err != nil {
		return knowledgeFail(err)
	}
	results := make([]map[string]any, 0, len(hits))
	for _, hit := range hits {
		results = append(results, hit.PublicJSON())
	}
	got := protocol.Success(fmt.Sprintf("Found %d matching knowledge items", len(results)), map[string]any{"results": results})
	if next != "" {
		got.Cursor = next
		got.Truncated = true
		got.Data = map[string]any{"results": results, "cursor": next}
	}
	return got
}
