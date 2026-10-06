package api

import (
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var metricWindows = map[string]int64{
	"1h":  3_600_000,
	"24h": 86_400_000,
	"7d":  604_800_000,
}

func writeOverview(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient) {
	workspaces := []map[string]any{}
	listed := callRunner(r, runner, protocol.OpWorkspaceList, map[string]any{"limit": 100})
	if listed.OK {
		mapped, _ := projectDashboard(protocol.OpWorkspaceList, listed.Data).(map[string]any)
		workspaces = asObjectList(mapped["workspaces"])
	}
	agents := []map[string]any{}
	agentsResult := listAgentsAcrossWorkspaces(r, runner, map[string]any{"limit": 100})
	if agentsResult.OK {
		mapped, _ := projectDashboard(protocol.OpAgentList, agentsResult.Data).(map[string]any)
		agents = asObjectList(mapped["agents"])
	}
	grants := []map[string]any{}
	grantsResult := callRunner(r, runner, protocol.OpPrivilegeGrantList, map[string]any{})
	if grantsResult.OK {
		mapped, _ := projectDashboard(protocol.OpPrivilegeGrantList, grantsResult.Data).(map[string]any)
		grants = asObjectList(mapped["grants"])
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": buildOverviewProjection(workspaces, agents, grants, time.Now().UnixMilli())})
}

func writeMetrics(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient) {
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "24h"
	}
	if _, ok := metricWindows[window]; !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid_request",
			"message": "window must be one of 1h, 24h, 7d",
		})
		return
	}
	events := listAuditEvents(r, runner)
	writeJSON(w, http.StatusOK, map[string]any{"data": buildMetricsProjection(events, window, time.Now().UnixMilli(), 12)})
}

func writeReliability(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient) {
	serversResult := callRunner(r, runner, protocol.OpMCPServerList, map[string]any{})
	servers := []map[string]any{}
	if serversResult.OK {
		mapped, _ := projectDashboard(protocol.OpMCPServerList, serversResult.Data).(map[string]any)
		servers = asObjectList(mapped["servers"])
	}
	traces := make([]map[string]any, 0)
	if len(servers) > 5 {
		servers = servers[:5]
	}
	for _, server := range servers {
		id := str(server["id"])
		if id == "" {
			continue
		}
		result := callRunner(r, runner, protocol.OpMCPGatewayTraceList, map[string]any{"serverId": id, "limit": 100})
		if !result.OK {
			continue
		}
		mapped, _ := projectDashboard(protocol.OpMCPGatewayTraceList, result.Data).(map[string]any)
		traces = append(traces, asObjectList(mapped["traces"])...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": buildReliabilityProjection(traces)})
}

func listAuditEvents(r *http.Request, runner *mcp.RunnerClient) []map[string]any {
	result := callRunner(r, runner, protocol.OpAuditList, map[string]any{"limit": 100})
	if !result.OK {
		return []map[string]any{}
	}
	mapped, _ := projectDashboard(protocol.OpAuditList, result.Data).(map[string]any)
	return asObjectList(mapped["events"])
}

func buildOverviewProjection(workspaces, agents, grants []map[string]any, nowMs int64) map[string]any {
	if workspaces == nil {
		workspaces = []map[string]any{}
	}
	if agents == nil {
		agents = []map[string]any{}
	}
	if grants == nil {
		grants = []map[string]any{}
	}
	attention := make([]map[string]any, 0)
	for _, workspace := range workspaces {
		id := str(workspace["workspaceId"])
		status := str(workspace["status"])
		if status == "FAILED" {
			attention = append(attention, map[string]any{
				"id": "workspace-failed-" + id, "label": "Workspace setup failed",
				"detail": "Review the failure and recover if the checkout is worth keeping.",
				"href":   "/dashboard/workspaces/" + url.PathEscape(id) + "/summary",
			})
		}
		if status == "NETWORK_QUARANTINED" {
			attention = append(attention, map[string]any{
				"id": "workspace-quarantined-" + id, "label": "Workspace network quarantined",
				"detail": "Egress was revoked, so dependency access is denied.",
				"href":   "/dashboard/workspaces/" + url.PathEscape(id) + "/summary",
			})
		}
	}
	for _, workspace := range expiringWithin(workspaces, nowMs, 15) {
		id := str(workspace["workspaceId"])
		attention = append(attention, map[string]any{
			"id": "workspace-expiring-" + id, "label": "Lease expires soon",
			"detail": "Renew the lease or finalize before the workspace is reaped.",
			"href":   "/dashboard/workspaces/" + url.PathEscape(id) + "/summary",
		})
	}
	for _, agent := range agents {
		status := str(agent["status"])
		if status != "FAILED" && status != "LIMIT_EXCEEDED" && status != "TIMED_OUT" {
			continue
		}
		id := str(agent["agentId"])
		attention = append(attention, map[string]any{
			"id": "agent-" + id, "label": "Agent " + firstUnderscoreToSpace(strings.ToLower(status)),
			"detail": "Open the agent for its terminal reason and usage.",
			"href":   "/dashboard/agents/" + url.PathEscape(id),
		})
	}
	if len(grants) > 0 {
		attention = append(attention, map[string]any{
			"id": "pending-approvals", "label": strconv.Itoa(len(grants)) + " pending approval(s)",
			"detail": "Privilege requests are waiting for a decision.",
			"href":   "/dashboard/approvals",
		})
	}

	runningAgents := make([]map[string]any, 0)
	for _, agent := range agents {
		if str(agent["status"]) == "RUNNING" {
			runningAgents = append(runningAgents, agent)
		}
	}
	activeWorkspaces := 0
	for _, workspace := range workspaces {
		if str(workspace["status"]) == "ACTIVE" {
			activeWorkspaces++
		}
	}
	runningCost := int64(0)
	for _, agent := range runningAgents {
		runningCost += numberInt64(asObject(agent["usage"])["costMicros"])
	}
	buckets := make([]map[string]any, 0, 3)
	for _, minutes := range []int{15, 60, 240} {
		label := strconv.Itoa(minutes) + " min"
		if minutes >= 60 {
			label = strconv.Itoa(minutes/60) + " h"
		}
		buckets = append(buckets, map[string]any{
			"windowMinutes": minutes, "label": label, "count": len(expiringWithin(workspaces, nowMs, minutes)),
		})
	}

	type startEntry struct {
		at    int64
		agent map[string]any
	}
	starts := make([]startEntry, 0, len(agents))
	for _, agent := range agents {
		at, ok := parseInstant(firstValue(agent["startedAt"], agent["createdAt"]))
		if !ok {
			continue
		}
		starts = append(starts, startEntry{at: at, agent: agent})
	}
	agentOutcomes := make([]map[string]any, 0)
	costSeries := make([]map[string]any, 0)
	scope := "no agents on record"
	if len(starts) > 0 {
		scope = "retained agents, bucketed by start time"
		min := starts[0].at
		max := starts[0].at
		for _, entry := range starts {
			if entry.at < min {
				min = entry.at
			}
			if entry.at > max {
				max = entry.at
			}
		}
		bucketsCount := 8
		if max-min < 60_000 {
			bucketsCount = 1
		}
		bucketMs := float64(1)
		if bucketsCount > 1 {
			bucketMs = float64(max-min) / float64(bucketsCount)
		}
		for index := 0; index < bucketsCount; index++ {
			from := float64(min) + float64(index)*bucketMs
			to := float64(min) + float64(index+1)*bucketMs
			if index == bucketsCount-1 {
				to = float64(max) + 1
			}
			segments := map[string]int{"succeeded": 0, "attention": 0, "cancelled": 0, "running": 0, "other": 0}
			costMicros := int64(0)
			for _, entry := range starts {
				if float64(entry.at) >= from && float64(entry.at) < to {
					segments[outcomeGroup(str(entry.agent["status"]))]++
					costMicros += numberInt64(asObject(entry.agent["usage"])["costMicros"])
				}
			}
			at := time.UnixMilli(int64(from)).UTC()
			tick := strconv.Itoa(index + 1)
			agentOutcomes = append(agentOutcomes, map[string]any{
				"at": at.Format(time.RFC3339Nano), "label": at.Format("2006-01-02 15:04:05"), "tick": tick, "segments": segments,
			})
			costSeries = append(costSeries, map[string]any{
				"at": at.Format(time.RFC3339Nano), "label": at.Format("15:04:05"), "tick": tick, "value": float64(costMicros) / 1_000_000,
			})
		}
	}

	usageByProfile := map[string]map[string]any{}
	budgetBurn := make([]map[string]any, 0)
	for _, agent := range agents {
		usage := asObject(agent["usage"])
		budget := asObject(agent["budget"])
		profileID := str(agent["profileId"])
		if profileID == "" {
			profileID = "unprofiled"
		}
		entry, ok := usageByProfile[profileID]
		if !ok {
			entry = map[string]any{"profileId": profileID, "inputTokens": 0, "outputTokens": 0, "costMicros": 0}
			usageByProfile[profileID] = entry
		}
		entry["inputTokens"] = numberInt64(entry["inputTokens"]) + numberInt64(usage["inputTokens"])
		entry["outputTokens"] = numberInt64(entry["outputTokens"]) + numberInt64(usage["outputTokens"])
		entry["costMicros"] = numberInt64(entry["costMicros"]) + numberInt64(usage["costMicros"])
		if str(agent["status"]) == "RUNNING" {
			budgetBurn = append(budgetBurn, map[string]any{
				"agentId": str(agent["agentId"]), "profileId": profileID,
				"inputTokens": numberInt64(usage["inputTokens"]), "maxInputTokens": numberInt64(budget["maxInputTokens"]),
				"outputTokens": numberInt64(usage["outputTokens"]), "maxOutputTokens": numberInt64(budget["maxOutputTokens"]),
				"costMicros": numberInt64(usage["costMicros"]), "maxCostMicros": numberInt64(budget["maxCostMicros"]),
			})
		}
	}
	usageRows := make([]map[string]any, 0, len(usageByProfile))
	for _, entry := range usageByProfile {
		usageRows = append(usageRows, entry)
	}
	sort.Slice(usageRows, func(i, j int) bool {
		return numberInt64(usageRows[i]["costMicros"]) > numberInt64(usageRows[j]["costMicros"])
	})
	sort.Slice(budgetBurn, func(i, j int) bool {
		left := float64(numberInt64(budgetBurn[i]["costMicros"])) / math.Max(1, float64(numberInt64(budgetBurn[i]["maxCostMicros"])))
		right := float64(numberInt64(budgetBurn[j]["costMicros"])) / math.Max(1, float64(numberInt64(budgetBurn[j]["maxCostMicros"])))
		return left > right
	})
	return map[string]any{
		"attention":        attention,
		"running":          map[string]any{"agents": len(runningAgents), "workspaces": activeWorkspaces},
		"cost":             map[string]any{"scope": "running agents", "costMicros": runningCost, "agentCount": len(runningAgents)},
		"expiring":         buckets,
		"usageByProfile":   usageRows,
		"budgetBurn":       budgetBurn,
		"agentOutcomes":    agentOutcomes,
		"costSeries":       costSeries,
		"agentSeriesScope": scope,
		"generatedAt":      time.UnixMilli(nowMs).UTC().Format(time.RFC3339Nano),
	}
}

func buildMetricsProjection(events []map[string]any, window string, nowMs int64, buckets int) map[string]any {
	span := metricWindows[window]
	since := nowMs - span
	filtered := make([]map[string]any, 0, len(events))
	categories := map[string]int{}
	for _, event := range events {
		at, ok := parseInstant(event["createdAt"])
		if !ok || at < since {
			continue
		}
		filtered = append(filtered, event)
		key := str(event["subjectType"])
		if key == "" {
			key = "other"
		}
		categories[key]++
	}
	if buckets < 1 {
		buckets = 12
	}
	if buckets > 48 {
		buckets = 48
	}
	bucketMs := float64(span) / float64(buckets)
	series := make([]map[string]any, 0, buckets)
	for index := 0; index < buckets; index++ {
		series = append(series, map[string]any{
			"at":    time.UnixMilli(since + int64(float64(index)*bucketMs)).UTC().Format(time.RFC3339Nano),
			"count": 0,
		})
	}
	for _, event := range filtered {
		at, _ := parseInstant(event["createdAt"])
		index := int(math.Floor(float64(at-since) / bucketMs))
		if index < 0 {
			index = 0
		}
		if index > buckets-1 {
			index = buckets - 1
		}
		series[index]["count"] = series[index]["count"].(int) + 1
	}
	return map[string]any{
		"window":     window,
		"since":      time.UnixMilli(since).UTC().Format(time.RFC3339Nano),
		"scope":      "retained audit events in the last " + window,
		"eventCount": len(filtered),
		"categories": categories,
		"series":     series,
	}
}

func buildReliabilityProjection(traces []map[string]any) map[string]any {
	type bucket struct {
		serverName string
		durations  []float64
		success    int
		error      int
	}
	byServer := map[string]*bucket{}
	order := make([]string, 0)
	for _, trace := range traces {
		serverID := str(trace["serverId"])
		if serverID == "" {
			serverID = "unknown"
		}
		entry, ok := byServer[serverID]
		if !ok {
			name := str(trace["serverName"])
			if name == "" {
				name = serverID
			}
			entry = &bucket{serverName: name}
			byServer[serverID] = entry
			order = append(order, serverID)
		}
		if duration, ok := asFloat(trace["durationMs"]); ok && !math.IsNaN(duration) && !math.IsInf(duration, 0) {
			entry.durations = append(entry.durations, duration)
		}
		status := strings.ToLower(str(trace["status"]))
		if status == "error" || status == "failed" || traceErrorCode(trace) {
			entry.error++
			continue
		}
		entry.success++
	}
	servers := make([]map[string]any, 0, len(order))
	total := 0
	for _, serverID := range order {
		entry := byServer[serverID]
		sorted := append([]float64{}, entry.durations...)
		sort.Float64s(sorted)
		row := map[string]any{
			"serverId":   serverID,
			"serverName": entry.serverName,
			"success":    entry.success,
			"error":      entry.error,
			"calls":      entry.success + entry.error,
		}
		if p50, ok := percentile(sorted, 0.5); ok {
			row["p50Ms"] = p50
		}
		if p95, ok := percentile(sorted, 0.95); ok {
			row["p95Ms"] = p95
		}
		total += entry.success + entry.error
		servers = append(servers, row)
	}
	return map[string]any{"servers": servers, "totalCalls": total}
}

func percentile(sorted []float64, fraction float64) (float64, bool) {
	if len(sorted) == 0 {
		return 0, false
	}
	index := int(math.Ceil(fraction*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index > len(sorted)-1 {
		index = len(sorted) - 1
	}
	return sorted[index], true
}

func expiringWithin(workspaces []map[string]any, nowMs int64, minutes int) []map[string]any {
	limit := int64(minutes) * 60_000
	out := make([]map[string]any, 0)
	for _, workspace := range workspaces {
		at, ok := parseInstant(workspace["expiresAt"])
		if !ok {
			continue
		}
		ms := at - nowMs
		if ms > 0 && ms <= limit {
			out = append(out, workspace)
		}
	}
	return out
}

func outcomeGroup(status string) string {
	switch status {
	case "SUCCEEDED":
		return "succeeded"
	case "FAILED", "TIMED_OUT", "LIMIT_EXCEEDED":
		return "attention"
	case "CANCELLED":
		return "cancelled"
	case "RUNNING", "SPAWNING", "CANCELLING":
		return "running"
	default:
		return "other"
	}
}

func firstUnderscoreToSpace(value string) string {
	return strings.Replace(value, "_", " ", 1)
}

func traceErrorCode(trace map[string]any) bool {
	v, ok := trace["errorCode"]
	if !ok || v == nil {
		return false
	}
	if s, isString := v.(string); isString && s == "" {
		return false
	}
	return true
}

func asObject(v any) map[string]any {
	obj, _ := v.(map[string]any)
	if obj == nil {
		return map[string]any{}
	}
	return obj
}

func numberInt64(v any) int64 {
	if i, ok := asInt(v); ok {
		return int64(i)
	}
	return 0
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float32:
		return float64(n), true
	default:
		if i, ok := asInt(v); ok {
			return float64(i), true
		}
		return 0, false
	}
}

func parseInstant(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), !math.IsNaN(n)
	case time.Time:
		return n.UnixMilli(), true
	case string:
		s := strings.TrimSpace(n)
		if s == "" {
			return 0, false
		}
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
			return ms, true
		}
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UnixMilli(), true
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UnixMilli(), true
		}
		return 0, false
	default:
		return 0, false
	}
}
