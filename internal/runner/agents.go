package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/agent"
	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	maxAgentsPerWorkspace = 128
	maxPromptBytes        = 131_072
	maxMessageBytes       = 65_536
	maxLogBytes           = 262_144
	maxToolResultText     = 2 * 1024 * 1024
)

var allowedProxyOps = map[string]struct{}{
	"files_list":         {},
	"files_read":         {},
	"files_write":        {},
	"files_apply_patch":  {},
	"files_delete":       {},
	"files_move":         {},
	"files_mkdir":        {},
	"grep_search":        {},
	"symbols_search":     {},
	"symbols_references": {},
}

var agentStatuses = map[string]struct{}{
	"SPAWNING":       {},
	"RUNNING":        {},
	"CANCELLING":     {},
	"SUCCEEDED":      {},
	"FAILED":         {},
	"CANCELLED":      {},
	"TIMED_OUT":      {},
	"LIMIT_EXCEEDED": {},
	"INTERRUPTED":    {},
}

type agentBudget struct {
	TTLSeconds      int   `json:"ttlSeconds"`
	MaxOutputBytes  int   `json:"maxOutputBytes"`
	MaxInputTokens  int   `json:"maxInputTokens"`
	MaxOutputTokens int   `json:"maxOutputTokens"`
	MaxCostMicros   int64 `json:"maxCostMicros"`
}

type agentRecord struct {
	id              string
	ownerID         string
	workspaceID     string
	parentAgentID   string
	profileID       string
	proxyOperations []string
	status          string
	generation      int
	createdAt       time.Time
	startedAt       time.Time
	terminalAt      time.Time
	expiresAt       time.Time
	budget          agentBudget
	terminalReason  string
	idempotencyKey  string
	fingerprint     string
	promptHash      string
	logs            []byte
	messages        map[string]agentMessage
	containerName   string
	networkName     string
	leaseID         string
	channel         *agent.Channel
	usage           agent.Usage
}

type agentMessage struct {
	agentID        string
	idempotencyKey string
	state          string
	fingerprint    string
}

type agentHub struct {
	mu       sync.Mutex
	byID     map[string]*agentRecord
	byKey    map[string]string
	launcher *agent.Launcher
	gateway  *agent.ControlClient
	profiles map[string]agent.Profile
	exec     func(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult
	seenReq  map[string]struct{}
}

func newAgentHub() *agentHub {
	return &agentHub{byID: map[string]*agentRecord{}, byKey: map[string]string{}, seenReq: map[string]struct{}{}}
}

func (h *agentHub) withRuntime(launcher *agent.Launcher, gateway *agent.ControlClient, profiles map[string]agent.Profile) *agentHub {
	h.launcher = launcher
	h.gateway = gateway
	h.profiles = profiles
	return h
}

type agentInput struct {
	WorkspaceID     string   `json:"workspaceId"`
	Prompt          string   `json:"prompt"`
	IdempotencyKey  string   `json:"idempotencyKey"`
	ProfileID       string   `json:"profileId"`
	ParentAgentID   string   `json:"parentAgentId"`
	ProxyOperations []string `json:"proxyOperations"`
	TTLSeconds      int      `json:"ttlSeconds"`
	MaxOutputBytes  int      `json:"maxOutputBytes"`
	MaxInputTokens  int      `json:"maxInputTokens"`
	MaxOutputTokens int      `json:"maxOutputTokens"`
	MaxCostMicros   *int64   `json:"maxCostMicros"`
	AgentID         string   `json:"agentId"`
	Cursor          string   `json:"cursor"`
	LimitBytes      int      `json:"limitBytes"`
	Limit           *int     `json:"limit"`
	Mode            string   `json:"mode"`
	Message         string   `json:"message"`
	Reason          string   `json:"reason"`
	Status          string   `json:"status"`
}

func (s *Service) agentDispatch(req protocol.RunnerRequest) protocol.ToolResult {
	var in agentInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &in); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid agent input", false)
		}
	}
	rec, errRes := s.resolveWorkspace(req.OwnerID, in.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	switch req.Operation {
	case protocol.OpAgentSpawn:
		return s.agents.spawn(context.Background(), rec, in)
	case protocol.OpAgentStatus:
		return s.agents.status(rec, in)
	case protocol.OpAgentLogs:
		return s.agents.logs(rec, in)
	case protocol.OpAgentMessage:
		return s.agents.message(rec, in)
	case protocol.OpAgentCancel:
		return s.agents.cancel(context.Background(), rec, in)
	case protocol.OpAgentList:
		return s.agents.list(rec, in)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unsupported agent operation", false)
	}
}

func (h *agentHub) spawn(ctx context.Context, ws store.Record, in agentInput) protocol.ToolResult {
	if ws.Status != store.StatusActive {
		return protocol.Fail(protocol.ErrorNotFound, "workspace was not found", false)
	}
	if ws.NetworkProfile != protocol.NetworkNone {
		return protocol.Fail(protocol.ErrorConflict, "agents require a network-disabled workspace; open a separate workspace with networkProfile \"network-none\"", false)
	}
	if !protocol.ValidIdempotencyKey(in.IdempotencyKey) {
		return protocol.Fail(protocol.ErrorInvalidInput, "idempotencyKey is required", false)
	}
	if !protocol.ValidModelProfileID(in.ProfileID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "profileId is required", false)
	}
	if strings.TrimSpace(in.Prompt) == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "prompt is required", false)
	}
	if len([]byte(in.Prompt)) > maxPromptBytes {
		return protocol.Fail(protocol.ErrorLimitExceeded, "agent prompt exceeds the configured byte limit", false)
	}
	if in.ParentAgentID != "" && !protocol.ValidOpaqueID(protocol.PrefixAgent, in.ParentAgentID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid parentAgentId", false)
	}
	ops, errMsg := normalizeProxyOps(in.ProxyOperations)
	if errMsg != "" {
		return protocol.Fail(protocol.ErrorInvalidInput, errMsg, false)
	}
	budget := defaultBudget(in)
	fp := spawnFingerprint(in.Prompt, in.ProfileID, in.ParentAgentID, ops, budget)
	promptHash := sha256Hex(in.Prompt)
	mapKey := ws.OwnerID + ":" + ws.ID + ":" + in.IdempotencyKey

	h.mu.Lock()
	defer h.mu.Unlock()
	if priorID, ok := h.byKey[mapKey]; ok {
		rec := h.byID[priorID]
		if rec.fingerprint != fp {
			return protocol.Fail(protocol.ErrorConflict, "Idempotency key reused with different agent parameters", false)
		}
		return protocol.Success("Agent spawn replayed", spawnView(rec, true))
	}
	if in.ParentAgentID != "" {
		parent := h.byID[in.ParentAgentID]
		if parent == nil || parent.workspaceID != ws.ID || parent.ownerID != ws.OwnerID {
			return protocol.Fail(protocol.ErrorNotFound, "parent agent not found", false)
		}
	}
	n := 0
	for _, rec := range h.byID {
		if rec.workspaceID == ws.ID {
			n++
		}
	}
	if n >= maxAgentsPerWorkspace {
		return protocol.Fail(protocol.ErrorLimitExceeded, "too many agents", false)
	}
	now := time.Now().UTC()
	rec := &agentRecord{
		id:              protocol.NewOpaqueID(protocol.PrefixAgent),
		ownerID:         ws.OwnerID,
		workspaceID:     ws.ID,
		parentAgentID:   in.ParentAgentID,
		profileID:       in.ProfileID,
		proxyOperations: ops,
		status:          "SPAWNING",
		generation:      1,
		createdAt:       now,
		expiresAt:       now.Add(time.Duration(budget.TTLSeconds) * time.Second),
		budget:          budget,
		idempotencyKey:  in.IdempotencyKey,
		fingerprint:     fp,
		promptHash:      promptHash,
		messages:        map[string]agentMessage{},
		leaseID:         protocol.NewOpaqueID(protocol.PrefixAgentLease),
	}
	h.byID[rec.id] = rec
	h.byKey[mapKey] = rec.id
	h.launchOrFail(ctx, rec, ws, in.Prompt)
	return protocol.Success("Agent spawn accepted", spawnView(rec, false))
}

func (h *agentHub) launchOrFail(ctx context.Context, rec *agentRecord, ws store.Record, prompt string) {
	if h.launcher == nil {
		rec.status = "FAILED"
		rec.terminalAt = time.Now().UTC()
		rec.terminalReason = "agent runtime is not wired in this Go-port slice"
		return
	}
	lease := ""
	if h.gateway != nil {
		ttl := time.Until(rec.expiresAt)
		if ttl < time.Second {
			ttl = time.Second
		}
		token, err := h.gateway.Issue(ctx, agent.IssueInput{
			LeaseID: rec.leaseID, AgentID: rec.id, ProfileID: rec.profileID,
			TTL: ttl, MaxInputTokens: rec.budget.MaxInputTokens, MaxOutputTokens: rec.budget.MaxOutputTokens, MaxCostMicros: rec.budget.MaxCostMicros,
		})
		if err != nil {
			rec.status = "FAILED"
			rec.terminalAt = time.Now().UTC()
			rec.terminalReason = "model gateway lease issue failed"
			return
		}
		lease = token
	}
	got, err := h.launcher.Launch(ctx, rec.id, ws.ID, rec.generation)
	rec.containerName = got.ContainerName
	rec.networkName = got.NetworkName
	rec.channel = got.Channel
	if err != nil {
		rec.status = "FAILED"
		rec.terminalAt = time.Now().UTC()
		rec.terminalReason = "agent container launch failed"
		_ = h.launcher.Cleanup(ctx, got)
		if h.gateway != nil {
			_ = h.gateway.Revoke(ctx, rec.leaseID)
		}
		return
	}
	if rec.channel != nil {
		deadlineMs := int(time.Until(rec.expiresAt) / time.Millisecond)
		if deadlineMs < 1_000 {
			deadlineMs = 1_000
		}
		if err := rec.channel.Send(agent.StartRecord{
			Type: "start", RequestID: rec.id, AgentID: rec.id, Prompt: prompt, Tools: rec.proxyOperations,
			Gateway: agent.StartGateway{Profile: rec.profileID, Lease: lease},
			Model: agent.StartModel{
				ID: rec.profileID, Name: rec.profileID, API: "openai-completions",
				ContextWindow: rec.budget.MaxInputTokens + rec.budget.MaxOutputTokens,
				MaxTokens:     rec.budget.MaxOutputTokens,
			},
			Limits: agent.StartLimits{
				DeadlineMs: deadlineMs, MaxEvents: 10_000, MaxOutputBytes: rec.budget.MaxOutputBytes,
				MaxEventBytes: 65_536, MaxToolResultBytes: 4 * 1024 * 1024,
			},
		}); err != nil {
			rec.status = "FAILED"
			rec.terminalAt = time.Now().UTC()
			rec.terminalReason = "agent protocol start failed"
			rec.channel.CloseInput()
			_ = h.launcher.Cleanup(ctx, got)
			return
		}
		go h.consume(rec)
	}
	rec.status = "RUNNING"
	rec.startedAt = time.Now().UTC()
}

func (h *agentHub) consume(rec *agentRecord) {
	for rec.channel != nil {
		out, err := rec.channel.Recv()
		if err != nil {
			h.mu.Lock()
			if rec.status == "RUNNING" || rec.status == "SPAWNING" {
				rec.status = "INTERRUPTED"
				rec.terminalAt = time.Now().UTC()
				rec.terminalReason = "agent runtime exited before terminal record"
			}
			h.mu.Unlock()
			return
		}
		h.mu.Lock()
		switch out.Type {
		case "event":
			rec.logs = appendLog(rec.logs, out.Event)
			h.mu.Unlock()
		case "usage":
			if out.Usage != nil {
				rec.usage = *out.Usage
			}
			h.mu.Unlock()
		case "tool_request":
			h.mu.Unlock()
			h.proxyTool(rec, out)
		case "tool_cancel":
			h.mu.Unlock()
		case "terminal":
			rec.status = out.State
			rec.terminalAt = time.Now().UTC()
			rec.terminalReason = out.Error
			if out.Usage != nil {
				rec.usage = *out.Usage
			}
			h.mu.Unlock()
			return
		default:
			h.mu.Unlock()
		}
	}
}

func (h *agentHub) proxyTool(rec *agentRecord, out agent.OutputRecord) {
	if rec.channel == nil {
		return
	}
	reply := func(msg string, isError bool) {
		_ = rec.channel.Send(agent.ToolResultRecord{
			Type: "tool_result", RequestID: out.RequestID, Final: true, IsError: isError,
			Content: []agent.ToolResultText{{Type: "text", Text: msg}},
		})
	}
	if rec.status != "RUNNING" || rec.channel == nil {
		reply(toolErrorJSON("agent tool execution lost its lifecycle fence"), true)
		return
	}
	granted := false
	for _, op := range rec.proxyOperations {
		if op == out.Operation {
			granted = true
			break
		}
	}
	if !granted {
		reply(toolErrorJSON("proxy operation is not granted"), true)
		return
	}
	h.mu.Lock()
	key := rec.id + "\x00" + out.RequestID
	if _, dup := h.seenReq[key]; dup {
		h.mu.Unlock()
		reply(toolErrorJSON("duplicate proxy request ID"), true)
		return
	}
	h.seenReq[key] = struct{}{}
	h.mu.Unlock()
	if _, ok := allowedProxyOps[out.Operation]; !ok {
		reply(toolErrorJSON("proxy operation is not granted"), true)
		return
	}
	input := map[string]any{}
	if len(out.Input) > 0 {
		_ = json.Unmarshal(out.Input, &input)
	}
	input["workspaceId"] = rec.workspaceID
	raw, _ := json.Marshal(input)
	if h.exec == nil {
		reply(toolErrorJSON("proxy tool execution failed"), true)
		return
	}
	result := h.exec(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: rec.ownerID, Operation: protocol.Operation(out.Operation), Input: raw,
	})
	h.mu.Lock()
	still := rec.status == "RUNNING"
	h.mu.Unlock()
	if !still {
		reply(toolErrorJSON("agent tool execution lost its lifecycle fence"), true)
		return
	}
	serialized, err := json.Marshal(result)
	if err != nil || len(serialized) > maxToolResultText {
		reply(toolErrorJSON("tool result exceeded the agent protocol bound"), true)
		return
	}
	reply(string(serialized), !result.OK)
}

func toolErrorJSON(message string) string {
	raw, _ := json.Marshal(map[string]any{
		"ok": false, "message": message,
		"error":     map[string]any{"code": "TOOL_ERROR", "message": message, "retryable": false},
		"truncated": false,
	})
	return string(raw)
}

func appendLog(dst, event []byte) []byte {
	if len(event) == 0 {
		return dst
	}
	if len(dst)+len(event)+1 > maxLogBytes {
		return dst
	}
	if len(dst) > 0 {
		dst = append(dst, '\n')
	}
	return append(dst, event...)
}

func (h *agentHub) status(ws store.Record, in agentInput) protocol.ToolResult {
	hasID := in.AgentID != ""
	hasKey := in.IdempotencyKey != ""
	if hasID == hasKey {
		return protocol.Fail(protocol.ErrorInvalidInput, "either agentId or idempotencyKey must be provided, but not both", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var rec *agentRecord
	if hasID {
		if !protocol.ValidOpaqueID(protocol.PrefixAgent, in.AgentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "agentId is required", false)
		}
		rec = h.byID[in.AgentID]
	} else {
		if !protocol.ValidIdempotencyKey(in.IdempotencyKey) {
			return protocol.Fail(protocol.ErrorInvalidInput, "idempotencyKey is required", false)
		}
		id := h.byKey[ws.OwnerID+":"+ws.ID+":"+in.IdempotencyKey]
		rec = h.byID[id]
	}
	if rec == nil || rec.workspaceID != ws.ID || rec.ownerID != ws.OwnerID {
		return protocol.Fail(protocol.ErrorNotFound, "agent not found", false)
	}
	return protocol.Success("Agent status", rec.public())
}

func (h *agentHub) logs(ws store.Record, in agentInput) protocol.ToolResult {
	if !protocol.ValidOpaqueID(protocol.PrefixAgent, in.AgentID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "agentId is required", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.owned(ws, in.AgentID)
	if rec == nil {
		return protocol.Fail(protocol.ErrorNotFound, "agent not found", false)
	}
	offset := 0
	if in.Cursor != "" {
		n, err := strconv.Atoi(in.Cursor)
		if err != nil || n < 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid log cursor", false)
		}
		offset = n
	}
	limit := in.LimitBytes
	if limit <= 0 {
		limit = 65_536
	}
	if limit < 1_024 || limit > maxLogBytes {
		return protocol.Fail(protocol.ErrorInvalidInput, "limitBytes must be between 1024 and 262144", false)
	}
	total := len(rec.logs)
	if offset > total {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid log cursor", false)
	}
	end := offset + limit
	if end > total {
		end = total
	}
	data := map[string]any{
		"agentId":            rec.id,
		"cursor":             strconv.Itoa(offset),
		"nextCursor":         strconv.Itoa(end),
		"retainedBaseCursor": "0",
		"truncated":          false,
		"hasMore":            end < total,
		"events":             []any{},
		"chunk":              string(rec.logs[offset:end]),
	}
	got := protocol.Success("Agent logs", data)
	if end < total {
		got.Truncated = true
		got.Cursor = strconv.Itoa(end)
	}
	return got
}

func (h *agentHub) message(ws store.Record, in agentInput) protocol.ToolResult {
	if !protocol.ValidOpaqueID(protocol.PrefixAgent, in.AgentID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "agentId is required", false)
	}
	if !protocol.ValidIdempotencyKey(in.IdempotencyKey) {
		return protocol.Fail(protocol.ErrorInvalidInput, "idempotencyKey is required", false)
	}
	if in.Mode != "steer" && in.Mode != "followUp" {
		return protocol.Fail(protocol.ErrorInvalidInput, "mode must be steer or followUp", false)
	}
	if strings.TrimSpace(in.Message) == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "message is required", false)
	}
	if len([]byte(in.Message)) > maxMessageBytes {
		return protocol.Fail(protocol.ErrorLimitExceeded, "agent message exceeds the configured byte limit", false)
	}
	fp := sha256Hex(in.Mode + "\x00" + in.Message)
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.owned(ws, in.AgentID)
	if rec == nil {
		return protocol.Fail(protocol.ErrorNotFound, "agent not found", false)
	}
	if prior, ok := rec.messages[in.IdempotencyKey]; ok {
		if prior.fingerprint != fp {
			return protocol.Fail(protocol.ErrorConflict, "Idempotency key reused with different message parameters", false)
		}
		return protocol.Success("Agent message replayed", map[string]any{
			"agentId": prior.agentID, "idempotencyKey": prior.idempotencyKey, "state": prior.state, "replayed": true,
		})
	}
	msg := agentMessage{agentID: rec.id, idempotencyKey: in.IdempotencyKey, state: "REJECTED", fingerprint: fp}
	if rec.channel != nil && rec.status == "RUNNING" {
		if err := rec.channel.Send(agent.MessageRecord{Type: "message", RequestID: in.IdempotencyKey, Behavior: in.Mode, Text: in.Message}); err != nil {
			msg.state = "UNKNOWN"
		} else {
			msg.state = "SENT"
		}
	} else if rec.status == "RUNNING" || rec.status == "SPAWNING" {
		msg.state = "UNKNOWN"
	}
	rec.messages[in.IdempotencyKey] = msg
	label := "Agent message rejected"
	if msg.state == "SENT" {
		label = "Agent message accepted"
	} else if msg.state == "UNKNOWN" {
		label = "Agent message outcome unknown"
	}
	return protocol.Success(label, map[string]any{
		"agentId": msg.agentID, "idempotencyKey": msg.idempotencyKey, "state": msg.state, "replayed": false,
	})
}

func (h *agentHub) cancel(ctx context.Context, ws store.Record, in agentInput) protocol.ToolResult {
	if !protocol.ValidOpaqueID(protocol.PrefixAgent, in.AgentID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "agentId is required", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	root := h.owned(ws, in.AgentID)
	if root == nil {
		return protocol.Fail(protocol.ErrorNotFound, "agent not found", false)
	}
	affected := []string{}
	now := time.Now().UTC()
	for _, rec := range h.byID {
		if rec.workspaceID != ws.ID || rec.ownerID != ws.OwnerID {
			continue
		}
		if rec.id == root.id || rec.parentAgentID == root.id {
			if rec.status == "SPAWNING" || rec.status == "RUNNING" || rec.status == "CANCELLING" {
				if rec.channel != nil {
					_ = rec.channel.Send(agent.CancelRecord{Type: "cancel", RequestID: rec.id, Reason: in.Reason})
					rec.channel.CloseInput()
				}
				rec.status = "CANCELLED"
				rec.terminalAt = now
				rec.terminalReason = in.Reason
				if rec.terminalReason == "" {
					rec.terminalReason = "cancelled by owner"
				}
				rec.generation++
				if h.launcher != nil && rec.containerName != "" {
					_ = h.launcher.Cleanup(ctx, agent.LaunchResult{ContainerName: rec.containerName, NetworkName: rec.networkName})
				}
				if h.gateway != nil && rec.leaseID != "" {
					_ = h.gateway.Revoke(ctx, rec.leaseID)
				}
			}
			affected = append(affected, rec.id)
		}
	}
	sort.Strings(affected)
	return protocol.Success("Agent cancellation complete", map[string]any{
		"agentId":          root.id,
		"status":           root.status,
		"affectedAgentIds": affected,
	})
}

func (h *agentHub) list(ws store.Record, in agentInput) protocol.ToolResult {
	limit := 50
	if in.Limit != nil {
		limit = *in.Limit
	}
	if limit < 1 || limit > 100 {
		return protocol.Fail(protocol.ErrorInvalidInput, "limit must be between 1 and 100", false)
	}
	if in.Status != "" {
		if _, ok := agentStatuses[in.Status]; !ok {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid agent status", false)
		}
	}
	if in.ParentAgentID != "" && !protocol.ValidOpaqueID(protocol.PrefixAgent, in.ParentAgentID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid parentAgentId", false)
	}
	offset := 0
	if in.Cursor != "" {
		n, err := strconv.Atoi(in.Cursor)
		if err != nil || n < 1 {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid agent cursor", false)
		}
		offset = n
	}
	h.mu.Lock()
	all := make([]*agentRecord, 0)
	for _, rec := range h.byID {
		if rec.workspaceID != ws.ID || rec.ownerID != ws.OwnerID {
			continue
		}
		if in.ParentAgentID != "" && rec.parentAgentID != in.ParentAgentID {
			continue
		}
		if in.Status != "" && rec.status != in.Status {
			continue
		}
		all = append(all, rec)
	}
	h.mu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].createdAt.Before(all[j].createdAt) })
	if offset > len(all) {
		offset = len(all)
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	page := make([]map[string]any, 0, end-offset)
	for _, rec := range all[offset:end] {
		page = append(page, rec.public())
	}
	data := map[string]any{"agents": page}
	got := protocol.Success("Agents listed", data)
	if end < len(all) {
		got.Cursor = strconv.Itoa(end)
		data["nextCursor"] = got.Cursor
		got.Data = data
	}
	return got
}

func (h *agentHub) owned(ws store.Record, id string) *agentRecord {
	rec := h.byID[id]
	if rec == nil || rec.workspaceID != ws.ID || rec.ownerID != ws.OwnerID {
		return nil
	}
	return rec
}

func spawnView(rec *agentRecord, replayed bool) map[string]any {
	return map[string]any{
		"agentId":    rec.id,
		"status":     rec.status,
		"generation": rec.generation,
		"replayed":   replayed,
	}
}

func (r *agentRecord) public() map[string]any {
	var parent any
	if r.parentAgentID != "" {
		parent = r.parentAgentID
	}
	var started any
	if !r.startedAt.IsZero() {
		started = r.startedAt.UTC().Format(time.RFC3339Nano)
	}
	var terminal any
	if !r.terminalAt.IsZero() {
		terminal = r.terminalAt.UTC().Format(time.RFC3339Nano)
	}
	return map[string]any{
		"agentId":         r.id,
		"workspaceId":     r.workspaceID,
		"parentAgentId":   parent,
		"profileId":       r.profileID,
		"proxyOperations": r.proxyOperations,
		"status":          r.status,
		"generation":      r.generation,
		"createdAt":       r.createdAt.UTC().Format(time.RFC3339Nano),
		"startedAt":       started,
		"terminalAt":      terminal,
		"expiresAt":       r.expiresAt.UTC().Format(time.RFC3339Nano),
		"budget":          r.budget,
		"usage":           map[string]any{"inputTokens": r.usage.Input, "outputTokens": r.usage.Output, "costMicros": int64(r.usage.Cost * 1_000_000)},
		"terminalReason":  r.terminalReason,
		"outcomeUnknown":  false,
	}
}

func normalizeProxyOps(ops []string) ([]string, string) {
	if len(ops) < 1 || len(ops) > len(allowedProxyOps) {
		return nil, "proxyOperations is required"
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		if _, ok := allowedProxyOps[op]; !ok {
			return nil, "requested proxy operation exceeds the selected profile"
		}
		if _, ok := seen[op]; ok {
			return nil, "proxy operations must be unique"
		}
		seen[op] = struct{}{}
		out = append(out, op)
	}
	return out, ""
}

func defaultBudget(in agentInput) agentBudget {
	b := agentBudget{
		TTLSeconds:      in.TTLSeconds,
		MaxOutputBytes:  in.MaxOutputBytes,
		MaxInputTokens:  in.MaxInputTokens,
		MaxOutputTokens: in.MaxOutputTokens,
		MaxCostMicros:   10_000_000,
	}
	if b.TTLSeconds <= 0 {
		b.TTLSeconds = 900
	}
	if b.MaxOutputBytes <= 0 {
		b.MaxOutputBytes = 262_144
	}
	if b.MaxInputTokens <= 0 {
		b.MaxInputTokens = 200_000
	}
	if b.MaxOutputTokens <= 0 {
		b.MaxOutputTokens = 32_000
	}
	if in.MaxCostMicros != nil {
		b.MaxCostMicros = *in.MaxCostMicros
	}
	return b
}

func spawnFingerprint(prompt, profile, parent string, ops []string, budget agentBudget) string {
	sorted := append([]string{}, ops...)
	sort.Strings(sorted)
	raw, _ := json.Marshal(map[string]any{
		"prompt": prompt, "profileId": profile, "parentAgentId": parent,
		"proxyOperations": sorted, "budget": budget,
	})
	return sha256Hex(string(raw))
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
