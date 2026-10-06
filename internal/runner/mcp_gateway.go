package runner

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/mcpgw"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

type mcpHeader struct {
	Name      string
	Kind      string
	Value     string
	SecretRef string
}

type mcpToolRec struct {
	ID            string
	UpstreamName  string
	QualifiedName string
	Description   string
	InputSchema   any
	Annotations   map[string]any
	Availability  string
	Permission    protocol.GatewayPermission
	DiscoveredAt  int64
}

type mcpServerRec struct {
	ID                 string
	PrincipalID        string
	Name               string
	Description        string
	Transport          string
	Endpoint           string
	Headers            []mcpHeader
	Enabled            bool
	Status             string
	PermissionDefault  protocol.GatewayPermission
	Generation         int
	CreatedAt          int64
	UpdatedAt          int64
	LastConnectedAt    int64
	LastCheckedAt      int64
	LastError          string
	Tools              []*mcpToolRec
	PermissionOverride map[string]protocol.GatewayPermission
}

type mcpTraceRec struct {
	ID            string
	PrincipalID   string
	ServerID      any
	ServerName    string
	Tool          any
	Operation     string
	ClientID      any
	DurationMs    int
	Status        string
	ErrorCode     any
	ErrorMessage  any
	RequestBytes  any
	ResponseBytes any
	CreatedAt     int64
	rowID         int
}

type mcpGatewayHub struct {
	mu     sync.Mutex
	byID   map[string]*mcpServerRec
	byName map[string]string
	traces []mcpTraceRec
	seq    int
}

func newMCPGatewayHub() *mcpGatewayHub {
	return &mcpGatewayHub{byID: map[string]*mcpServerRec{}, byName: map[string]string{}}
}

func (s *Service) mcpGateway(req protocol.RunnerRequest) protocol.ToolResult {
	if s.mcpStore != nil {
		return s.mcpStore.Handle(req)
	}
	if s.mcpGW == nil {
		s.mcpGW = newMCPGatewayHub()
	}
	return s.mcpGW.handle(req)
}

func (h *mcpGatewayHub) handle(req protocol.RunnerRequest) protocol.ToolResult {
	principal := strings.TrimSpace(req.OwnerID)
	if principal == "" {
		principal = "owner"
	}
	switch req.Operation {
	case protocol.OpMCPGatewayCatalog:
		return h.catalog(principal, req.Input)
	case protocol.OpMCPServerGetCredentials:
		return h.credentials(principal, req.Input)
	case protocol.OpMCPServerCreate:
		return h.create(principal, req.Input)
	case protocol.OpMCPServerReplaceTools:
		return h.replaceTools(principal, req.Input)
	case protocol.OpMCPServerSetPermissions:
		return h.setPermissions(principal, req.Input)
	case protocol.OpMCPServerConnectionResult:
		return h.recordConnectionResult(principal, req.Input)
	case protocol.OpMCPGatewayTraceAppend:
		return h.appendTrace(principal, req.Input)
	case protocol.OpMCPGatewayTraceList:
		return h.listTraces(principal, req.Input)
	case protocol.OpMCPServerList:
		return h.list(principal, req.Input)
	case protocol.OpMCPServerGet:
		return h.get(principal, req.Input)
	case protocol.OpMCPServerUpdate:
		return h.update(principal, req.Input)
	case protocol.OpMCPServerDelete:
		return h.delete(principal, req.Input)
	case protocol.OpMCPServerSetEnabled:
		return h.setEnabled(principal, req.Input)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown operation", false)
	}
}

type catalogFilter struct {
	ServerID      string `json:"serverId"`
	QualifiedName string `json:"qualifiedName"`
}

type createInput struct {
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	Transport          string         `json:"transport"`
	Endpoint           string         `json:"endpoint"`
	Headers            []createHeader `json:"headers"`
	PermissionDefault  string         `json:"permissionDefault"`
	Enabled            *bool          `json:"enabled"`
	ExpectedGeneration *int           `json:"expectedGeneration"`
}

type createHeader struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

type replaceToolsInput struct {
	ServerID string             `json:"serverId"`
	Tools    []replaceToolInput `json:"tools"`
	Status   string             `json:"status"`
	Cap      int                `json:"cap"`
}

type replaceToolInput struct {
	UpstreamName string         `json:"upstreamName"`
	Description  string         `json:"description"`
	InputSchema  any            `json:"inputSchema"`
	Annotations  map[string]any `json:"annotations"`
	Availability string         `json:"availability"`
}

type credentialsInput struct {
	ServerID string `json:"serverId"`
	ToolName string `json:"toolName"`
	Purpose  string `json:"purpose"`
}

func (h *mcpGatewayHub) catalog(principal string, raw json.RawMessage) protocol.ToolResult {
	var filter catalogFilter
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &filter); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid catalog filter", false)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	servers := make([]map[string]any, 0)
	tools := make([]map[string]any, 0)
	seen := map[string]bool{}
	for _, rec := range h.byID {
		if rec.PrincipalID != principal {
			continue
		}
		if filter.ServerID != "" && rec.ID != filter.ServerID {
			continue
		}
		includeServer := filter.QualifiedName == ""
		for _, tool := range rec.Tools {
			if filter.QualifiedName != "" && tool.QualifiedName != filter.QualifiedName {
				continue
			}
			includeServer = true
			tools = append(tools, toolView(rec, tool))
		}
		if includeServer && !seen[rec.ID] {
			servers = append(servers, serverView(rec))
			seen[rec.ID] = true
		}
	}
	return protocol.Success("MCP gateway catalog", map[string]any{"servers": servers, "tools": tools})
}

func (h *mcpGatewayHub) create(principal string, raw json.RawMessage) protocol.ToolResult {
	var in createInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid MCP server create input", false)
	}
	if in.ExpectedGeneration != nil && *in.ExpectedGeneration != 0 {
		return protocol.Fail(protocol.ErrorConflict, "stale MCP server generation", false)
	}
	name := strings.TrimSpace(in.Name)
	if !validServerName(name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "server name must be 1-63 lowercase letters, numbers, or hyphens", false)
	}
	transport := strings.TrimSpace(in.Transport)
	if transport == "stdio" {
		return protocol.Fail(protocol.ErrorInvalidInput, "stdio downstream transport is not supported; use streamable-http or sse", false)
	}
	if transport != string(protocol.GatewayTransportStreamableHTTP) && transport != string(protocol.GatewayTransportSSE) {
		return protocol.Fail(protocol.ErrorInvalidInput, "transport must be 'streamable-http' or 'sse'", false)
	}
	endpoint := strings.TrimSpace(in.Endpoint)
	if endpoint == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "endpoint is required", false)
	}
	headers, err := parseCreateHeaders(in.Headers)
	if err != "" {
		return protocol.Fail(protocol.ErrorInvalidInput, err, false)
	}
	if transport == string(protocol.GatewayTransportSSE) {
		for _, header := range headers {
			if header.Kind == "secret" {
				return protocol.Fail(protocol.ErrorInvalidInput, "authenticated SSE is not supported: credentials are attached only to the configured endpoint, so use transport streamable-http for a server that needs a secret header", false)
			}
		}
	}
	perm := protocol.GatewayPermission(strings.TrimSpace(in.PermissionDefault))
	if perm == "" {
		perm = protocol.GatewayAllow
	}
	if perm != protocol.GatewayAllow && perm != protocol.GatewayDeny {
		return protocol.Fail(protocol.ErrorInvalidInput, "permissionDefault must be allow or deny", false)
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	now := time.Now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	key := principal + "\x00" + name
	if _, exists := h.byName[key]; exists {
		return protocol.Fail(protocol.ErrorConflict, "MCP server name already exists", false)
	}
	status := "unknown"
	if !enabled {
		status = "disabled"
	}
	rec := &mcpServerRec{
		ID:                 protocol.NewOpaqueID(protocol.PrefixMCPServer),
		PrincipalID:        principal,
		Name:               name,
		Description:        in.Description,
		Transport:          transport,
		Endpoint:           endpoint,
		Headers:            headers,
		Enabled:            enabled,
		Status:             status,
		PermissionDefault:  perm,
		Generation:         1,
		CreatedAt:          now,
		UpdatedAt:          now,
		PermissionOverride: map[string]protocol.GatewayPermission{},
	}
	h.byID[rec.ID] = rec
	h.byName[key] = rec.ID
	return protocol.Success("MCP server created", serverView(rec))
}

func (h *mcpGatewayHub) replaceTools(principal string, raw json.RawMessage) protocol.ToolResult {
	var in replaceToolsInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid replace tools input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	cap := in.Cap
	if cap <= 0 {
		cap = 500
	}
	status := strings.TrimSpace(in.Status)
	if status == "" {
		status = "connected"
	}
	now := time.Now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[in.ServerID]
	if rec == nil || rec.PrincipalID != principal {
		return protocol.Fail(protocol.ErrorNotFound, "MCP server is unavailable", false)
	}
	next := make([]*mcpToolRec, 0, len(in.Tools))
	for i, tool := range in.Tools {
		name := strings.TrimSpace(tool.UpstreamName)
		if !validToolName(name) {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid upstream tool name", false)
		}
		availability := strings.TrimSpace(tool.Availability)
		if availability == "" {
			availability = "available"
		}
		desc := tool.Description
		if i >= cap {
			availability = "unavailable"
			desc = "tool omitted: per-server tool limit reached"
		}
		schema := tool.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		perm := rec.PermissionDefault
		if override, ok := rec.PermissionOverride[name]; ok {
			perm = override
		}
		next = append(next, &mcpToolRec{
			ID:            protocol.NewOpaqueID(protocol.PrefixMCPTool),
			UpstreamName:  name,
			QualifiedName: protocol.QualifiedToolName(rec.Name, name),
			Description:   desc,
			InputSchema:   schema,
			Annotations:   tool.Annotations,
			Availability:  availability,
			Permission:    perm,
			DiscoveredAt:  now,
		})
	}
	rec.Tools = next
	rec.Status = status
	rec.LastCheckedAt = now
	if status == "connected" {
		rec.LastConnectedAt = now
		rec.LastError = ""
	}
	rec.UpdatedAt = now
	out := make([]map[string]any, 0, len(next))
	for _, tool := range next {
		out = append(out, toolView(rec, tool))
	}
	return protocol.Success("MCP tools replaced", map[string]any{"tools": out, "toolCount": len(in.Tools)})
}

func validGatewayStatus(status string) bool {
	switch status {
	case "unknown", "connected", "connecting", "disconnected", "error", "disabled":
		return true
	default:
		return false
	}
}

func (h *mcpGatewayHub) recordConnectionResult(principal string, raw json.RawMessage) protocol.ToolResult {
	var in struct {
		ServerID string  `json:"serverId"`
		Status   string  `json:"status"`
		Error    *string `json:"error"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid connection result input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	status := strings.TrimSpace(in.Status)
	if !validGatewayStatus(status) {
		return protocol.Fail(protocol.ErrorInvalidInput, "status is invalid", false)
	}
	now := time.Now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[in.ServerID]
	if rec == nil || rec.PrincipalID != principal {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	rec.Status = status
	rec.LastCheckedAt = now
	if status == "connected" {
		rec.LastConnectedAt = now
		rec.LastError = ""
	} else if in.Error != nil {
		rec.LastError = mcpgw.ScrubCredentialText(*in.Error, nil)
		if len(rec.LastError) > 500 {
			rec.LastError = rec.LastError[:500]
		}
	}
	rec.UpdatedAt = now
	return protocol.Success("MCP connection result recorded", serverView(rec))
}

func (h *mcpGatewayHub) setPermissions(principal string, raw json.RawMessage) protocol.ToolResult {
	var in struct {
		ServerID           string `json:"serverId"`
		PermissionDefault  string `json:"permissionDefault"`
		ExpectedGeneration int    `json:"expectedGeneration"`
		Tools              []struct {
			Name       string `json:"name"`
			Permission string `json:"permission"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid set permissions input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	perm := protocol.GatewayPermission(strings.TrimSpace(in.PermissionDefault))
	if perm != protocol.GatewayAllow && perm != protocol.GatewayDeny {
		return protocol.Fail(protocol.ErrorInvalidInput, "permissionDefault must be allow or deny", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[in.ServerID]
	if rec == nil || rec.PrincipalID != principal {
		return protocol.Fail(protocol.ErrorNotFound, "MCP server is unavailable", false)
	}
	if rec.Generation != in.ExpectedGeneration {
		return protocol.Fail(protocol.ErrorConflict, "stale MCP server generation", false)
	}
	next := map[string]protocol.GatewayPermission{}
	for _, tool := range in.Tools {
		name := strings.TrimSpace(tool.Name)
		if !validToolName(name) {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid upstream tool name", false)
		}
		p := protocol.GatewayPermission(strings.TrimSpace(tool.Permission))
		if p != protocol.GatewayAllow && p != protocol.GatewayDeny {
			return protocol.Fail(protocol.ErrorInvalidInput, "permission must be allow or deny", false)
		}
		next[name] = p
	}
	rec.PermissionDefault = perm
	rec.PermissionOverride = next
	for _, tool := range rec.Tools {
		if override, ok := next[tool.UpstreamName]; ok {
			tool.Permission = override
		} else {
			tool.Permission = perm
		}
	}
	rec.Generation++
	rec.UpdatedAt = time.Now().UnixMilli()
	return protocol.Success("MCP permissions updated", serverView(rec))
}

func (h *mcpGatewayHub) list(principal string, _ json.RawMessage) protocol.ToolResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	servers := make([]map[string]any, 0)
	for _, rec := range h.byID {
		if rec.PrincipalID != principal {
			continue
		}
		servers = append(servers, serverView(rec))
	}
	return protocol.Success("MCP servers listed", map[string]any{"servers": servers})
}

func (h *mcpGatewayHub) get(principal string, raw json.RawMessage) protocol.ToolResult {
	var in struct {
		ServerID string `json:"serverId"`
	}
	if err := json.Unmarshal(raw, &in); err != nil || !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[in.ServerID]
	if rec == nil || rec.PrincipalID != principal {
		return protocol.Fail(protocol.ErrorNotFound, "MCP server not found", false)
	}
	tools := make([]map[string]any, 0, len(rec.Tools))
	for _, tool := range rec.Tools {
		tools = append(tools, toolView(rec, tool))
	}
	return protocol.Success("MCP server retrieved", map[string]any{"server": serverView(rec), "tools": tools})
}

func (h *mcpGatewayHub) update(principal string, raw json.RawMessage) protocol.ToolResult {
	var in struct {
		ServerID           string         `json:"serverId"`
		ExpectedGeneration int            `json:"expectedGeneration"`
		Name               *string        `json:"name"`
		Description        *string        `json:"description"`
		Transport          *string        `json:"transport"`
		Endpoint           *string        `json:"endpoint"`
		Headers            []createHeader `json:"headers"`
		PermissionDefault  *string        `json:"permissionDefault"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid MCP server update input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[in.ServerID]
	if rec == nil || rec.PrincipalID != principal || rec.Generation != in.ExpectedGeneration {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	name := rec.Name
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
		if !validServerName(name) {
			return protocol.Fail(protocol.ErrorInvalidInput, "server name must be 1-63 lowercase letters, numbers, or hyphens", false)
		}
		if name != rec.Name {
			if existing, ok := h.byName[principal+"\x00"+name]; ok && existing != rec.ID {
				return protocol.Fail(protocol.ErrorConflict, "MCP server name already exists", false)
			}
		}
	}
	description := rec.Description
	if in.Description != nil {
		description = *in.Description
	}
	transport := rec.Transport
	if in.Transport != nil {
		transport = strings.TrimSpace(*in.Transport)
		if transport == "stdio" {
			return protocol.Fail(protocol.ErrorInvalidInput, "stdio downstream transport is not supported; use streamable-http or sse", false)
		}
		if transport != string(protocol.GatewayTransportStreamableHTTP) && transport != string(protocol.GatewayTransportSSE) {
			return protocol.Fail(protocol.ErrorInvalidInput, "transport must be 'streamable-http' or 'sse'", false)
		}
	}
	endpoint := rec.Endpoint
	if in.Endpoint != nil {
		endpoint = strings.TrimSpace(*in.Endpoint)
		if endpoint == "" {
			return protocol.Fail(protocol.ErrorInvalidInput, "endpoint is required", false)
		}
	}
	headers := rec.Headers
	if in.Headers != nil {
		parsed, errMsg := parseCreateHeaders(in.Headers)
		if errMsg != "" {
			return protocol.Fail(protocol.ErrorInvalidInput, errMsg, false)
		}
		headers = parsed
	}
	if transport == string(protocol.GatewayTransportSSE) {
		for _, header := range headers {
			if header.Kind == "secret" {
				return protocol.Fail(protocol.ErrorInvalidInput, "authenticated SSE is not supported: credentials are attached only to the configured endpoint, so use transport streamable-http for a server that needs a secret header", false)
			}
		}
	}
	perm := rec.PermissionDefault
	if in.PermissionDefault != nil {
		next := protocol.GatewayPermission(strings.TrimSpace(*in.PermissionDefault))
		if next != protocol.GatewayAllow && next != protocol.GatewayDeny {
			return protocol.Fail(protocol.ErrorInvalidInput, "permissionDefault must be allow or deny", false)
		}
		perm = next
	}
	if name != rec.Name {
		delete(h.byName, principal+"\x00"+rec.Name)
		h.byName[principal+"\x00"+name] = rec.ID
		for _, tool := range rec.Tools {
			tool.QualifiedName = protocol.QualifiedToolName(name, tool.UpstreamName)
		}
	}
	rec.Name = name
	rec.Description = description
	rec.Transport = transport
	rec.Endpoint = endpoint
	rec.Headers = headers
	rec.PermissionDefault = perm
	rec.Generation++
	rec.UpdatedAt = time.Now().UnixMilli()
	return protocol.Success("MCP server updated", serverView(rec))
}

func (h *mcpGatewayHub) setEnabled(principal string, raw json.RawMessage) protocol.ToolResult {
	var in struct {
		ServerID           string `json:"serverId"`
		Enabled            bool   `json:"enabled"`
		ExpectedGeneration int    `json:"expectedGeneration"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid MCP server enabled input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[in.ServerID]
	if rec == nil || rec.PrincipalID != principal || rec.Generation != in.ExpectedGeneration {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	rec.Enabled = in.Enabled
	if in.Enabled {
		if rec.Status == "disabled" {
			rec.Status = "unknown"
		}
	} else {
		rec.Status = "disabled"
	}
	rec.Generation++
	rec.UpdatedAt = time.Now().UnixMilli()
	message := "MCP server disabled"
	if in.Enabled {
		message = "MCP server enabled"
	}
	return protocol.Success(message, serverView(rec))
}

func (h *mcpGatewayHub) delete(principal string, raw json.RawMessage) protocol.ToolResult {
	var in struct {
		ServerID           string `json:"serverId"`
		ExpectedGeneration int    `json:"expectedGeneration"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid MCP server delete input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[in.ServerID]
	if rec == nil || rec.PrincipalID != principal || rec.Generation != in.ExpectedGeneration {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	delete(h.byID, rec.ID)
	delete(h.byName, principal+"\x00"+rec.Name)
	kept := h.traces[:0]
	for _, trace := range h.traces {
		if sid, ok := trace.ServerID.(string); ok && sid == rec.ID && trace.PrincipalID == principal {
			continue
		}
		kept = append(kept, trace)
	}
	h.traces = kept
	rec.Enabled = false
	rec.Status = "disabled"
	rec.Tools = nil
	rec.PermissionOverride = map[string]protocol.GatewayPermission{}
	rec.Generation++
	rec.UpdatedAt = time.Now().UnixMilli()
	return protocol.Success("MCP server deleted", serverView(rec))
}

func (h *mcpGatewayHub) credentials(principal string, raw json.RawMessage) protocol.ToolResult {
	var in credentialsInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid credentials input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	if in.Purpose != "execute" && in.Purpose != "connect" {
		return protocol.Fail(protocol.ErrorInvalidInput, "purpose must be execute or connect", false)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[in.ServerID]
	if rec == nil || rec.PrincipalID != principal {
		return protocol.Fail(protocol.ErrorNotFound, "MCP server is unavailable", false)
	}
	if !rec.Enabled {
		return protocol.Success("MCP server is disabled", map[string]any{"allowed": false, "reason": "server_disabled"})
	}
	if in.Purpose == "execute" {
		var tool *mcpToolRec
		if in.ToolName != "" {
			for _, candidate := range rec.Tools {
				if candidate.UpstreamName == in.ToolName {
					tool = candidate
					break
				}
			}
		}
		if tool == nil || tool.Permission != protocol.GatewayAllow {
			return protocol.Success("MCP tool access denied", map[string]any{"allowed": false, "reason": "tool_denied"})
		}
	}
	headers := map[string]string{}
	for _, header := range rec.Headers {
		if header.Kind == "secret" {
			return protocol.Fail(protocol.ErrorNotFound, "referenced secret "+header.SecretRef+" is unavailable", false)
		}
		if header.Value != "" {
			headers[header.Name] = header.Value
		}
	}
	return protocol.Success("MCP credentials resolved", map[string]any{
		"allowed":   true,
		"transport": rec.Transport,
		"endpoint":  rec.Endpoint,
		"headers":   headers,
	})
}

func (h *mcpGatewayHub) appendTrace(principal string, raw json.RawMessage) protocol.ToolResult {
	var in struct {
		ServerID      *string  `json:"serverId"`
		ServerName    string   `json:"serverName"`
		Tool          *string  `json:"tool"`
		Operation     string   `json:"operation"`
		ClientID      *string  `json:"clientId"`
		DurationMs    int      `json:"durationMs"`
		Status        string   `json:"status"`
		ErrorCode     *string  `json:"errorCode"`
		ErrorMessage  *string  `json:"errorMessage"`
		RequestBytes  *int     `json:"requestBytes"`
		ResponseBytes *int     `json:"responseBytes"`
		Secrets       []string `json:"secrets"`
		MaxRows       int      `json:"maxRows"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid trace append input", false)
	}
	name := strings.TrimSpace(in.ServerName)
	if name == "" || len(name) > 63 {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverName is required", false)
	}
	op := strings.TrimSpace(in.Operation)
	if op == "" || len(op) > 32 {
		return protocol.Fail(protocol.ErrorInvalidInput, "operation is required", false)
	}
	if in.DurationMs < 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "durationMs must be >= 0", false)
	}
	status := strings.TrimSpace(in.Status)
	if status != "success" && status != "error" && status != "denied" {
		return protocol.Fail(protocol.ErrorInvalidInput, "status must be success, error, or denied", false)
	}
	if in.ServerID != nil && *in.ServerID != "" && !protocol.ValidOpaqueID(protocol.PrefixMCPServer, *in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is invalid", false)
	}
	if len(in.Secrets) > 8 {
		return protocol.Fail(protocol.ErrorInvalidInput, "too many secrets", false)
	}
	maxRows := in.MaxRows
	if maxRows == 0 {
		maxRows = 20_000
	}
	if maxRows < 100 {
		maxRows = 100
	}
	if maxRows > 1_000_000 {
		maxRows = 1_000_000
	}
	var message any
	if in.ErrorMessage != nil && strings.TrimSpace(*in.ErrorMessage) != "" {
		out := mcpgw.ScrubCredentialText(*in.ErrorMessage, in.Secrets)
		if len(out) > 500 {
			out = out[:500]
		}
		message = out
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	rec := mcpTraceRec{
		ID:            protocol.NewOpaqueID(protocol.PrefixMCPTrace),
		PrincipalID:   principal,
		ServerID:      nilIfEmptyPtr(in.ServerID),
		ServerName:    name,
		Tool:          nilIfEmptyPtr(in.Tool),
		Operation:     op,
		ClientID:      nilIfEmptyPtr(in.ClientID),
		DurationMs:    in.DurationMs,
		Status:        status,
		ErrorCode:     nilIfEmptyPtr(in.ErrorCode),
		ErrorMessage:  message,
		RequestBytes:  nilIfInt(in.RequestBytes),
		ResponseBytes: nilIfInt(in.ResponseBytes),
		CreatedAt:     time.Now().UnixMilli(),
		rowID:         h.seq,
	}
	h.traces = append(h.traces, rec)
	kept := make([]mcpTraceRec, 0, len(h.traces))
	n := 0
	for i := len(h.traces) - 1; i >= 0; i-- {
		if h.traces[i].PrincipalID != principal {
			kept = append(kept, h.traces[i])
			continue
		}
		n++
		if n <= maxRows {
			kept = append(kept, h.traces[i])
		}
	}
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	h.traces = kept
	return protocol.Success("MCP trace recorded", map[string]any{"trace": memoryTraceView(rec)})
}

func (h *mcpGatewayHub) listTraces(principal string, raw json.RawMessage) protocol.ToolResult {
	var in struct {
		ServerID string `json:"serverId"`
		Limit    int    `json:"limit"`
		Cursor   string `json:"cursor"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid trace list input", false)
		}
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	cursorCreated, cursorID, hasCursor := parseMemoryTraceCursor(in.Cursor)
	h.mu.Lock()
	defer h.mu.Unlock()
	matches := make([]mcpTraceRec, 0)
	for i := len(h.traces) - 1; i >= 0; i-- {
		rec := h.traces[i]
		if rec.PrincipalID != principal {
			continue
		}
		if in.ServerID != "" {
			id, _ := rec.ServerID.(string)
			if id != in.ServerID {
				continue
			}
		}
		if hasCursor && (rec.CreatedAt > cursorCreated || (rec.CreatedAt == cursorCreated && rec.ID >= cursorID)) {
			continue
		}
		matches = append(matches, rec)
	}
	if len(matches) > 1 {
		for i := 0; i < len(matches); i++ {
			for j := i + 1; j < len(matches); j++ {
				if matches[i].CreatedAt < matches[j].CreatedAt || (matches[i].CreatedAt == matches[j].CreatedAt && matches[i].ID < matches[j].ID) {
					matches[i], matches[j] = matches[j], matches[i]
				}
			}
		}
	}
	if len(matches) > limit {
		matches = matches[:limit]
	}
	traces := make([]map[string]any, 0, len(matches))
	for _, rec := range matches {
		traces = append(traces, memoryTraceView(rec))
	}
	res := protocol.Success("MCP traces listed", map[string]any{"traces": traces})
	if len(traces) == limit && limit > 0 {
		last := traces[len(traces)-1]
		res.Cursor = strconv.FormatInt(last["createdAt"].(int64), 10) + "." + last["id"].(string)
	}
	return res
}

func memoryTraceView(rec mcpTraceRec) map[string]any {
	return map[string]any{
		"id":            rec.ID,
		"principalId":   rec.PrincipalID,
		"serverId":      rec.ServerID,
		"serverName":    rec.ServerName,
		"tool":          rec.Tool,
		"operation":     rec.Operation,
		"clientId":      rec.ClientID,
		"durationMs":    rec.DurationMs,
		"status":        rec.Status,
		"errorCode":     rec.ErrorCode,
		"errorMessage":  rec.ErrorMessage,
		"requestBytes":  rec.RequestBytes,
		"responseBytes": rec.ResponseBytes,
		"createdAt":     rec.CreatedAt,
	}
}

func nilIfEmptyPtr(v *string) any {
	if v == nil {
		return nil
	}
	s := strings.TrimSpace(*v)
	if s == "" {
		return nil
	}
	return s
}

func nilIfInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func parseMemoryTraceCursor(cursor string) (int64, string, bool) {
	sep := strings.IndexByte(cursor, '.')
	if sep <= 0 {
		return 0, "", false
	}
	created, err := strconv.ParseInt(cursor[:sep], 10, 64)
	if err != nil || created <= 0 {
		return 0, "", false
	}
	id := cursor[sep+1:]
	if id == "" {
		return 0, "", false
	}
	return created, id, true
}

func parseCreateHeaders(in []createHeader) ([]mcpHeader, string) {
	out := make([]mcpHeader, 0, len(in))
	for _, header := range in {
		name := strings.TrimSpace(header.Name)
		if name == "" {
			return nil, "header name is required"
		}
		if len(header.Value) == 0 {
			return nil, "header value is required"
		}
		var literal string
		if err := json.Unmarshal(header.Value, &literal); err == nil {
			out = append(out, mcpHeader{Name: name, Kind: "literal", Value: literal})
			continue
		}
		var ref struct {
			SecretRef string `json:"secretRef"`
		}
		if err := json.Unmarshal(header.Value, &ref); err != nil || strings.TrimSpace(ref.SecretRef) == "" {
			return nil, "header value must be a literal or secretRef"
		}
		out = append(out, mcpHeader{Name: name, Kind: "secret", SecretRef: strings.TrimSpace(ref.SecretRef)})
	}
	return out, ""
}

func serverView(rec *mcpServerRec) map[string]any {
	headers := make([]map[string]any, 0, len(rec.Headers))
	for _, header := range rec.Headers {
		item := map[string]any{"name": header.Name, "kind": header.Kind}
		if header.Kind == "secret" {
			item["secretRef"] = header.SecretRef
		} else {
			item["value"] = header.Value
		}
		headers = append(headers, item)
	}
	view := map[string]any{
		"id":                rec.ID,
		"principalId":       rec.PrincipalID,
		"name":              rec.Name,
		"description":       nilString(rec.Description),
		"transport":         rec.Transport,
		"endpoint":          rec.Endpoint,
		"headers":           headers,
		"enabled":           rec.Enabled,
		"status":            rec.Status,
		"toolCount":         len(rec.Tools),
		"lastConnectedAt":   nilUnix(rec.LastConnectedAt),
		"lastError":         nilString(rec.LastError),
		"lastCheckedAt":     nilUnix(rec.LastCheckedAt),
		"permissionDefault": string(rec.PermissionDefault),
		"generation":        rec.Generation,
		"createdAt":         rec.CreatedAt,
		"updatedAt":         rec.UpdatedAt,
	}
	return view
}

func toolView(rec *mcpServerRec, tool *mcpToolRec) map[string]any {
	schema := tool.InputSchema
	if schema == nil {
		schema = map[string]any{"type": "object"}
	}
	return map[string]any{
		"id":            tool.ID,
		"principalId":   rec.PrincipalID,
		"serverId":      rec.ID,
		"serverName":    rec.Name,
		"qualifiedName": tool.QualifiedName,
		"upstreamName":  tool.UpstreamName,
		"description":   tool.Description,
		"inputSchema":   schema,
		"annotations":   tool.Annotations,
		"availability":  tool.Availability,
		"permission":    string(tool.Permission),
		"discoveredAt":  tool.DiscoveredAt,
	}
}

func nilString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nilUnix(v int64) any {
	if v <= 0 {
		return nil
	}
	return v
}

func validServerName(name string) bool {
	if len(name) < 1 || len(name) > 63 {
		return false
	}
	c0 := name[0]
	if !((c0 >= 'a' && c0 <= 'z') || (c0 >= '0' && c0 <= '9')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validToolName(name string) bool {
	if len(name) < 1 || len(name) > 120 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' {
			continue
		}
		return false
	}
	return true
}
