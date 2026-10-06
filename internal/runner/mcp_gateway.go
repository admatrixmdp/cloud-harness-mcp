package runner

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

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

type mcpGatewayHub struct {
	mu     sync.Mutex
	byID   map[string]*mcpServerRec
	byName map[string]string
}

func newMCPGatewayHub() *mcpGatewayHub {
	return &mcpGatewayHub{byID: map[string]*mcpServerRec{}, byName: map[string]string{}}
}

func (s *Service) mcpGateway(req protocol.RunnerRequest) protocol.ToolResult {
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
