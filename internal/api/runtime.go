package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	agentLogContentLimit = 4_000
	agentFanOutLimit     = 100
	artifactChunkLimit   = 1_048_576
	runtimeOutputLimit   = 8_000
)

var worktreeNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)

var taskKeys = []string{"id", "name", "status", "exitCode", "dependsOn", "startedAt", "finishedAt", "durationMs", "cwd", "outputBytes"}
var sessionKeys = []string{"id", "name", "status", "cwd", "createdAt", "lastActivityAt", "closedAt", "cursor"}

var metadataKeys = []string{"id", "name", "state", "generation", "createdAt", "updatedAt", "deletedAt"}
var environmentKeys = []string{"id", "name", "state", "generation", "createdAt", "updatedAt", "deletedAt", "projectId"}
var secretKeys = []string{"id", "environmentId", "name", "description", "state", "version", "generation", "createdAt", "updatedAt", "deletedAt"}

var artifactKeys = []string{
	"artifactId", "logicalName", "sha256", "sizeBytes", "projectId", "environmentId", "workspaceId",
	"createdAt", "updatedAt", "expiresAt", "retentionMs", "generation",
}

var agentKeys = []string{
	"agentId", "workspaceId", "parentAgentId", "profileId", "status", "generation",
	"createdAt", "startedAt", "terminalAt", "expiresAt", "terminalReason", "outcomeUnknown", "proxyOperations",
}

var agentBudgetKeys = []string{"ttlSeconds", "maxOutputBytes", "maxInputTokens", "maxOutputTokens", "maxCostMicros"}
var agentUsageKeys = []string{"inputTokens", "outputTokens", "costMicros", "outputBytes", "eventCount", "toolTimeMs", "wallTimeMs"}

func requireArtifactID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("artifactId")
	if !protocol.ValidOpaqueID(protocol.PrefixArtifact, id) {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return "", false
	}
	return id, true
}

func requireAgentID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("agentId")
	if !protocol.ValidOpaqueID(protocol.PrefixAgent, id) {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return "", false
	}
	return id, true
}

func callRunner(r *http.Request, runner *mcp.RunnerClient, op protocol.Operation, input map[string]any) protocol.ToolResult {
	if runner == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "The workspace service is temporarily unavailable.", true)
	}
	if workspace, ok := input["workspaceId"].(string); ok && workspace == "" {
		delete(input, "workspaceId")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false)
	}
	if op.Dashboard() || op.Internal() {
		return runner.CallInternal(r.Context(), op, raw)
	}
	return runner.Call(r.Context(), op, raw)
}

func downloadArtifact(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient) {
	artifactID, ok := requireArtifactID(w, r)
	if !ok {
		return
	}
	offset := 0
	totalBytes := 0
	logicalName := "artifact.bin"
	expectedSHA := ""
	var chunks [][]byte
	for {
		result := callRunner(r, runner, protocol.OpArtifactRead, map[string]any{
			"artifactId": artifactID,
			"offset":     offset,
			"limit":      artifactChunkLimit,
		})
		if !result.OK {
			writeDashboardFail(w, result)
			return
		}
		data, _ := result.Data.(map[string]any)
		if name, _ := data["logicalName"].(string); name != "" {
			logicalName = name
		}
		if n, ok := asInt(data["totalBytes"]); ok {
			totalBytes = n
		}
		if sha, _ := data["sha256"].(string); sha != "" {
			expectedSHA = sha
		}
		content, _ := data["content"].(string)
		if n, ok := asInt(data["bytesReturned"]); ok && n > 0 && content != "" {
			buf, err := base64.StdEncoding.DecodeString(content)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal_error", "message": "artifact download integrity verification failed"})
				return
			}
			chunks = append(chunks, buf)
			offset += len(buf)
		}
		eof, _ := data["eof"].(bool)
		if eof || (totalBytes > 0 && offset >= totalBytes) {
			break
		}
		if content == "" {
			break
		}
	}
	full := joinBytes(chunks)
	sum := sha256.Sum256(full)
	if expectedSHA != "" && hex.EncodeToString(sum[:]) != expectedSHA {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal_error", "message": "artifact download integrity verification failed"})
		return
	}
	name := strings.NewReplacer(`"`, "", "\r", "", "\n", "").Replace(logicalName)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(full)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(full)
}

func listWorkspaceArtifacts(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient) {
	workspaceID := r.PathValue("workspaceId")
	if !protocol.ValidOpaqueID(protocol.PrefixWorkspace, workspaceID) {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return
	}
	result := callRunner(r, runner, protocol.OpArtifactList, map[string]any{"limit": 100})
	if !result.OK {
		writeDashboardFail(w, result)
		return
	}
	mapped, _ := projectDashboard(protocol.OpArtifactList, result.Data).(map[string]any)
	filtered := make([]map[string]any, 0)
	for _, item := range asObjectList(mapped["artifacts"]) {
		if str(item["workspaceId"]) == workspaceID {
			filtered = append(filtered, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"artifacts": filtered}, "truncated": result.Truncated})
}

func listDashboardAgents(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient) {
	filters := map[string]any{}
	if parent := r.URL.Query().Get("parentAgentId"); parent != "" {
		filters["parentAgentId"] = parent
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filters["status"] = status
	}
	if limit := queryInt(r, "limit"); limit > 0 {
		filters["limit"] = limit
	}
	var result protocol.ToolResult
	if workspaceID := r.URL.Query().Get("workspaceId"); workspaceID != "" {
		filters["workspaceId"] = workspaceID
		if cursor := r.URL.Query().Get("cursor"); cursor != "" {
			filters["cursor"] = cursor
		}
		result = callRunner(r, runner, protocol.OpAgentList, filters)
	} else {
		result = listAgentsAcrossWorkspaces(r, runner, filters)
	}
	if !result.OK {
		writeDashboardFail(w, result)
		return
	}
	mapped, _ := projectDashboard(protocol.OpAgentList, result.Data).(map[string]any)
	profileID := strings.TrimSpace(r.URL.Query().Get("profileId"))
	attention := r.URL.Query().Get("attention")
	agents := make([]map[string]any, 0)
	for _, agent := range asObjectList(mapped["agents"]) {
		if profileID != "" && str(agent["profileId"]) != profileID {
			continue
		}
		if attention != "" && agentNeedsAttention(agent) != (attention == "needs-attention") {
			continue
		}
		agents = append(agents, agent)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"agents": agents}, "truncated": result.Truncated})
}

func listAgentsAcrossWorkspaces(r *http.Request, runner *mcp.RunnerClient, filters map[string]any) protocol.ToolResult {
	listed := callRunner(r, runner, protocol.OpWorkspaceList, map[string]any{"limit": 100})
	if !listed.OK {
		return listed
	}
	data, _ := listed.Data.(map[string]any)
	ids := make([]string, 0)
	for _, row := range asObjectList(data["workspaces"]) {
		id := str(row["workspaceId"])
		if protocol.ValidOpaqueID(protocol.PrefixWorkspace, id) {
			ids = append(ids, id)
		}
	}
	limit := agentFanOutLimit
	if n, ok := asInt(filters["limit"]); ok && n > 0 && n <= 100 {
		limit = n
	}
	agents := make([]map[string]any, 0)
	truncated := listed.Truncated
	for _, id := range ids {
		input := map[string]any{"workspaceId": id, "limit": limit}
		if parent, _ := filters["parentAgentId"].(string); parent != "" {
			input["parentAgentId"] = parent
		}
		if status, _ := filters["status"].(string); status != "" {
			input["status"] = status
		}
		got := callRunner(r, runner, protocol.OpAgentList, input)
		if !got.OK {
			continue
		}
		truncated = truncated || got.Truncated
		page, _ := got.Data.(map[string]any)
		agents = append(agents, asObjectList(page["agents"])...)
	}
	sort.Slice(agents, func(i, j int) bool { return str(agents[i]["createdAt"]) > str(agents[j]["createdAt"]) })
	if len(agents) > limit {
		truncated = true
		agents = agents[:limit]
	}
	got := protocol.Success("agents", map[string]any{"agents": agents})
	got.Truncated = truncated
	return got
}

func writeActivity(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient, workspaceID string) {
	agentsResult := listAgentsAcrossWorkspaces(r, runner, map[string]any{"limit": 100})
	agents := []map[string]any{}
	if agentsResult.OK {
		mapped, _ := projectDashboard(protocol.OpAgentList, agentsResult.Data).(map[string]any)
		agents = asObjectList(mapped["agents"])
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": buildActivityProjection(listAuditEvents(r, runner), agents, workspaceID)})
}

func buildActivityProjection(events, agents []map[string]any, workspaceID string) map[string]any {
	scope := strings.TrimSpace(workspaceID)
	rows := make([]map[string]any, 0, len(events)+len(agents))
	for _, event := range events {
		if scope != "" && str(event["subjectId"]) != scope {
			continue
		}
		rows = append(rows, map[string]any{
			"at":       instantISO(event["createdAt"]),
			"category": categoryFor(event["action"], event["subjectType"]),
			"status":   "recorded",
			"actor":    strings.TrimSpace(str(event["subjectType"]) + " " + str(event["subjectId"])),
			"summary":  firstNonEmpty(str(event["action"]), "Audit event"),
			"durable":  true,
		})
	}
	for _, agent := range agents {
		if scope != "" && str(agent["workspaceId"]) != scope {
			continue
		}
		at := agent["startedAt"]
		if at == nil {
			at = agent["createdAt"]
		}
		id := str(agent["agentId"])
		rows = append(rows, map[string]any{
			"at":       instantISO(at),
			"category": "agents",
			"status":   strings.ToLower(str(agent["status"])),
			"actor":    str(agent["workspaceId"]),
			"summary":  "Agent " + id + " " + str(agent["status"]),
			"href":     "/dashboard/agents/" + id,
			"durable":  false,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return str(rows[i]["at"]) > str(rows[j]["at"]) })
	if len(rows) > 200 {
		rows = rows[:200]
	}
	return map[string]any{"events": rows}
}

func categoryFor(action, subjectType any) string {
	text := strings.ToLower(str(action) + " " + str(subjectType))
	switch {
	case strings.Contains(text, "agent"):
		return "agents"
	case strings.Contains(text, "task"):
		return "tasks"
	case strings.Contains(text, "mcp"), strings.Contains(text, "gateway"):
		return "mcp"
	case strings.Contains(text, "deploy"):
		return "deployments"
	default:
		return "audit"
	}
}

func projectAgent(raw any) map[string]any {
	obj, _ := raw.(map[string]any)
	out := pickKeys(obj, agentKeys...)
	budget, _ := obj["budget"].(map[string]any)
	usage, _ := obj["usage"].(map[string]any)
	out["budget"] = pickKeys(budget, agentBudgetKeys...)
	out["usage"] = pickKeys(usage, agentUsageKeys...)
	return out
}

func projectAgents(raw any) []map[string]any {
	rows := asObjectList(raw)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, projectAgent(row))
	}
	return out
}

func projectAgentLogEvents(raw any) []map[string]any {
	rows := asObjectList(raw)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		event := pickKeys(row, "cursor", "timestamp", "type")
		content := str(row["content"])
		if len(content) > agentLogContentLimit {
			content = content[:agentLogContentLimit] + "\n… truncated"
		}
		event["content"] = content
		out = append(out, event)
	}
	return out
}

func agentNeedsAttention(agent map[string]any) bool {
	status := str(agent["status"])
	if status == "FAILED" || status == "TIMED_OUT" || status == "LIMIT_EXCEEDED" {
		return true
	}
	unknown, _ := agent["outcomeUnknown"].(bool)
	return unknown
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func instantISO(v any) any {
	ms, ok := parseInstant(v)
	if !ok {
		return v
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func joinBytes(chunks [][]byte) []byte {
	n := 0
	for _, c := range chunks {
		n += len(c)
	}
	out := make([]byte, 0, n)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func requireTaskID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("taskId")
	if !protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return "", false
	}
	return id, true
}

func requireSessionID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("sessionId")
	if !protocol.ValidOpaqueID(protocol.PrefixSession, id) {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return "", false
	}
	return id, true
}

func validWorktreeName(name string) bool {
	return worktreeNameRe.MatchString(name)
}

func boundedOutput(value any) any {
	s, ok := value.(string)
	if !ok {
		return nil
	}
	if len(s) > runtimeOutputLimit {
		return s[:runtimeOutputLimit] + "\n… truncated"
	}
	return s
}

func firstValue(values ...any) any {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func projectTask(obj map[string]any) map[string]any {
	out := pickKeys(obj, taskKeys...)
	if output := boundedOutput(obj["output"]); output != nil {
		out["output"] = output
	}
	return out
}

func projectSession(obj map[string]any) map[string]any {
	out := pickKeys(obj, sessionKeys...)
	if output := boundedOutput(obj["output"]); output != nil {
		out["output"] = output
	}
	return out
}

func parseGitStatus(output string) map[string]any {
	lines := strings.Split(output, "\n")
	header := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "## ") {
			header = line
			break
		}
	}
	detail := strings.TrimSpace(strings.TrimPrefix(header, "## "))
	ahead := 0
	behind := 0
	if start := strings.Index(detail, "["); start >= 0 {
		end := strings.Index(detail[start:], "]")
		if end >= 0 {
			bracket := detail[start+1 : start+end]
			ahead = extractCount(bracket, "ahead ")
			behind = extractCount(bracket, "behind ")
		}
		detail = strings.TrimSpace(reBracket.ReplaceAllString(detail, ""))
	}
	left, right, _ := strings.Cut(detail, "...")
	entries := make([]map[string]any, 0)
	staged := 0
	modified := 0
	untracked := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "## ") {
			continue
		}
		xy := line
		if len(xy) >= 2 {
			xy = line[:2]
		}
		path := ""
		if len(line) > 3 {
			path = strings.TrimSpace(line[3:])
		}
		code := strings.TrimSpace(xy)
		entries = append(entries, map[string]any{"code": code, "path": path})
		if len(xy) > 0 && xy[0] != ' ' && xy[0] != '?' {
			staged++
		}
		if len(xy) > 1 && xy[1] != ' ' && xy[1] != '?' {
			modified++
		}
		if strings.TrimSpace(xy) == "??" {
			untracked++
		}
	}
	branch := left
	if branch == "" {
		branch = "detached"
	}
	out := map[string]any{
		"branch":    branch,
		"ahead":     ahead,
		"behind":    behind,
		"entries":   entries,
		"staged":    staged,
		"modified":  modified,
		"untracked": untracked,
	}
	if right != "" {
		out["upstream"] = right
	}
	return out
}

var reBracket = regexp.MustCompile(`\s*\[[^\]]+\]\s*`)

func extractCount(text, prefix string) int {
	idx := strings.Index(text, prefix)
	if idx < 0 {
		return 0
	}
	rest := text[idx+len(prefix):]
	n := 0
	for _, r := range rest {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func parseWorktrees(output string) []map[string]any {
	lines := strings.Split(output, "\n")
	out := make([]map[string]any, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		item := map[string]any{"path": fields[0]}
		if len(fields) > 1 {
			item["head"] = fields[1]
		}
		if len(fields) > 2 {
			branch := strings.Trim(strings.Join(fields[2:], " "), "[]")
			if branch != "" {
				item["branch"] = branch
			}
		}
		out = append(out, item)
	}
	return out
}
