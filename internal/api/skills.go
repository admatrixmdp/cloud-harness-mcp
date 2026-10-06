package api

import (
	"net/http"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var skillKeys = []string{"id", "slug", "displayName", "description", "kind", "provider", "sourceRef", "currentRevisionId", "state", "tags", "generation", "createdAt", "updatedAt", "version"}
var skillRevisionKeys = []string{"id", "skillSourceId", "parentRevisionId", "origin", "hasExecutableAssets", "createdAt", "version"}
var skillSetKeys = []string{"id", "name", "description", "generation", "createdAt", "updatedAt"}
var skillSetItemKeys = []string{"skillSetId", "ordinal", "skillSourceId", "revisionId", "name"}
var skillUsageSetKeys = []string{"skillSetId", "name"}
var skillUsageWorkspaceKeys = []string{"workspaceId", "status", "name", "revisionId"}
var skillImportJobKeys = []string{"id", "sourceKind", "sourceRef", "state", "progress", "result", "errorCode", "skillRevisionId", "createdAt", "updatedAt"}
var skillResolvedKeys = []string{"name", "tier", "skillSourceId", "revisionId", "contentSha256", "pinned"}
var skillExcludedKeys = []string{"name", "tier", "reason"}

func registerDashboardSkills(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("GET /api/v1/skills", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillList, map[string]any{})
	})))
	mux.Handle("GET /api/v1/skills/search", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := map[string]any{"query": r.URL.Query().Get("query")}
		if providers := r.URL.Query().Get("providers"); providers != "" {
			input["providers"] = strings.Split(providers, ",")
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillSearch, input)
	})))
	mux.Handle("POST /api/v1/skills", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillCreateCustom, body)
	})))))
	mux.Handle("POST /api/v1/skills/bulk", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillBulk, body)
	})))))
	mux.Handle("GET /api/v1/skills/{skillId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillGet, map[string]any{"skillId": id})
	})))
	mux.Handle("PATCH /api/v1/skills/{skillId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		body["skillId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillUpdate, body)
	})))))
	mux.Handle("POST /api/v1/skills/{skillId}/archive", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		body["skillId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillArchive, body)
	})))))
	mux.Handle("POST /api/v1/skills/{skillId}/restore", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		body["skillId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillRestore, body)
	})))))
	mux.Handle("GET /api/v1/skills/{skillId}/revisions", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillRevisionList, map[string]any{"skillId": id})
	})))
	mux.Handle("POST /api/v1/skills/{skillId}/revisions", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		body["skillId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillRevisionCreate, body)
	})))))
	mux.Handle("GET /api/v1/skills/{skillId}/revisions/{revisionId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		rev, ok := requirePrefixedID(w, r.PathValue("revisionId"), protocol.PrefixSkillRevision)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillRevisionGet, map[string]any{"skillId": id, "revisionId": rev})
	})))
	mux.Handle("POST /api/v1/skills/{skillId}/revisions/{revisionId}/fork", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		rev, ok := requirePrefixedID(w, r.PathValue("revisionId"), protocol.PrefixSkillRevision)
		if !ok {
			return
		}
		body["skillId"] = id
		body["revisionId"] = rev
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillRevisionFork, body)
	})))))
	mux.Handle("GET /api/v1/skills/{skillId}/diff", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		from, ok := requirePrefixedID(w, r.URL.Query().Get("from"), protocol.PrefixSkillRevision)
		if !ok {
			return
		}
		to, ok := requirePrefixedID(w, r.URL.Query().Get("to"), protocol.PrefixSkillRevision)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillRevisionDiff, map[string]any{"skillId": id, "fromRevisionId": from, "toRevisionId": to})
	})))
	mux.Handle("GET /api/v1/skills/{skillId}/usage", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("skillId"), protocol.PrefixSkillSource)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillUsage, map[string]any{"skillId": id})
	})))
	mux.Handle("GET /api/v1/skill-sets", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillSetList, map[string]any{})
	})))
	mux.Handle("POST /api/v1/skill-sets", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillSetCreate, body)
	})))))
	mux.Handle("POST /api/v1/skill-sets/preview", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillSetPreview, body)
	})))))
	mux.Handle("GET /api/v1/skill-sets/{skillSetId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("skillSetId"), protocol.PrefixSkillSet)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillSetGet, map[string]any{"skillSetId": id})
	})))
	mux.Handle("PATCH /api/v1/skill-sets/{skillSetId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("skillSetId"), protocol.PrefixSkillSet)
		if !ok {
			return
		}
		body["skillSetId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillSetUpdate, body)
	})))))
	mux.Handle("DELETE /api/v1/skill-sets/{skillSetId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("skillSetId"), protocol.PrefixSkillSet)
		if !ok {
			return
		}
		body["skillSetId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillSetDelete, body)
	})))))
	mux.Handle("GET /api/v1/skill-imports/{jobId}", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := requirePrefixedID(w, r.PathValue("jobId"), protocol.PrefixSkillImportJob)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillImportStatus, map[string]any{"jobId": id})
	})))
	mux.Handle("POST /api/v1/skill-imports", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillImportStart, body)
	})))))
	mux.Handle("POST /api/v1/skill-imports/{jobId}/cancel", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id, ok := requirePrefixedID(w, r.PathValue("jobId"), protocol.PrefixSkillImportJob)
		if !ok {
			return
		}
		body["jobId"] = id
		proxyDashboard(w, r, opts.Runner, protocol.OpSkillImportCancel, body)
	})))))
}

func projectSkillRevision(obj map[string]any) map[string]any {
	out := pickKeys(obj, skillRevisionKeys...)
	if diff, ok := obj["diff"].(string); ok {
		out["diff"] = diff
	}
	return out
}

func projectSkillBulk(obj map[string]any) map[string]any {
	raw, _ := obj["results"].([]any)
	results := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		item, _ := entry.(map[string]any)
		row := pickKeys(item, "skillId", "name")
		row["ok"] = item["ok"] == true
		if err, ok := item["error"].(string); ok {
			row["error"] = err
		}
		if skill, ok := item["skill"].(map[string]any); ok {
			row["skill"] = pickKeys(skill, skillKeys...)
		}
		results = append(results, row)
	}
	return map[string]any{"results": results}
}

func projectSkillPreview(obj map[string]any) map[string]any {
	out := pickKeys(obj, "generation", "stale")
	out["resolved"] = projectObjects(obj["resolved"], skillResolvedKeys...)
	out["excluded"] = projectObjects(obj["excluded"], skillExcludedKeys...)
	conflicts := make([]map[string]any, 0)
	for _, row := range asObjectList(obj["conflicts"]) {
		conflicts = append(conflicts, pickKeys(row, "name", "candidates", "candidateCount"))
	}
	out["conflicts"] = conflicts
	return out
}
