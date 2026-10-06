package gateway

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const unknownToolMessage = "unknown or inaccessible MCP tool"

// CatalogCaller is the API→runner RPC used by the live gateway.
type CatalogCaller interface {
	Call(ctx context.Context, op protocol.Operation, input json.RawMessage) protocol.ToolResult
}

// Live loads the runner catalog and posts allowed tools through the
// SSRF-gated DownstreamClient. Denied execute never opens a socket.
type Live struct {
	Runner   CatalogCaller
	Endpoint EndpointOptions
}

type catalogView struct {
	Servers []catalogServer
	Tools   []catalogTool
}

type catalogServer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Endpoint  string `json:"endpoint"`
	Transport string `json:"transport"`
}

type catalogTool struct {
	ServerID      string         `json:"serverId"`
	ServerName    string         `json:"serverName"`
	QualifiedName string         `json:"qualifiedName"`
	UpstreamName  string         `json:"upstreamName"`
	Description   string         `json:"description"`
	InputSchema   any            `json:"inputSchema"`
	Annotations   map[string]any `json:"annotations"`
	Availability  string         `json:"availability"`
	Permission    string         `json:"permission"`
}

type credentialsView struct {
	Allowed   bool              `json:"allowed"`
	Reason    string            `json:"reason"`
	Transport string            `json:"transport"`
	Endpoint  string            `json:"endpoint"`
	Headers   map[string]string `json:"headers"`
}

// Dispatch handles one of the five meta-tools against the runner catalog.
func (l *Live) Dispatch(ctx context.Context, name string, input map[string]any) protocol.ToolResult {
	if l == nil || l.Runner == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "Runner is unavailable", true)
	}
	switch name {
	case protocol.GatewayToolSearch:
		query, _ := input["query"].(string)
		server, _ := input["server"].(string)
		limit := 5
		if n, ok := input["limit"].(float64); ok {
			limit = int(n)
		}
		return l.search(ctx, query, server, limit)
	case protocol.GatewayToolInspect:
		tool, _ := input["tool"].(string)
		return l.inspect(ctx, tool)
	case protocol.GatewayToolExecute:
		tool, _ := input["tool"].(string)
		args, _ := input["arguments"].(map[string]any)
		return l.execute(ctx, tool, args)
	case protocol.GatewayToolPermissions:
		tool, _ := input["tool"].(string)
		server, _ := input["server"].(string)
		return l.permissions(ctx, tool, server)
	case protocol.GatewayToolStatus:
		return l.status(ctx)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown gateway tool", false)
	}
}

func (l *Live) search(ctx context.Context, query, server string, limit int) protocol.ToolResult {
	if strings.TrimSpace(query) == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "query is required", false)
	}
	catalog, errRes, ok := l.loadCatalog(ctx, nil)
	if !ok {
		return errRes
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 25 {
		limit = 25
	}
	q := strings.ToLower(query)
	matches := make([]map[string]any, 0)
	for _, tool := range searchable(catalog) {
		if server != "" && tool.ServerName != server {
			continue
		}
		haystack := strings.ToLower(tool.QualifiedName + " " + tool.Description + " " + tool.UpstreamName)
		if !strings.Contains(haystack, q) {
			continue
		}
		matches = append(matches, map[string]any{
			"tool":        tool.QualifiedName,
			"server":      tool.ServerName,
			"description": tool.Description,
		})
		if len(matches) >= limit {
			break
		}
	}
	return protocol.Success("search results", map[string]any{"results": matches, "tools": matches})
}

func (l *Live) inspect(ctx context.Context, qualified string) protocol.ToolResult {
	tool, _, errRes, ok := l.resolveTool(ctx, qualified)
	if !ok {
		return errRes
	}
	schema := tool.InputSchema
	if schema == nil {
		schema = map[string]any{"type": "object"}
	}
	return protocol.Success("tool schema", map[string]any{
		"name":         tool.QualifiedName,
		"tool":         tool.QualifiedName,
		"server":       tool.ServerName,
		"description":  tool.Description,
		"inputSchema":  schema,
		"annotations":  tool.Annotations,
		"permission":   tool.Permission,
		"availability": tool.Availability,
	})
}

func (l *Live) execute(ctx context.Context, qualified string, arguments map[string]any) protocol.ToolResult {
	tool, server, errRes, ok := l.resolveTool(ctx, qualified)
	if !ok {
		return errRes
	}
	if tool.Availability == "unavailable" {
		return protocol.Fail(protocol.ErrorInvalidInput, "tool is unavailable", false)
	}
	creds, errRes, ok := l.credentials(ctx, server.ID, tool.UpstreamName, "execute")
	if !ok {
		return errRes
	}
	if !creds.Allowed {
		reason := creds.Reason
		if reason == "" {
			reason = "tool_denied"
		}
		return protocol.Success("MCP tool access denied", map[string]any{
			"tool":    tool.QualifiedName,
			"server":  server.Name,
			"allowed": false,
			"reason":  reason,
		})
	}
	endpoint := creds.Endpoint
	if endpoint == "" {
		endpoint = server.Endpoint
	}
	validated, err := ValidateEndpoint(endpoint, l.Endpoint)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	client := DownstreamClient{
		Endpoint:  validated.URL,
		Addresses: validated.Addresses,
		Headers:   creds.Headers,
	}
	result := client.Call(ctx, tool.UpstreamName, arguments)
	return redactResult(result, secretsFrom(creds.Headers))
}

func (l *Live) permissions(ctx context.Context, qualified, server string) protocol.ToolResult {
	if qualified != "" {
		tool, _, errRes, ok := l.resolveTool(ctx, qualified)
		if !ok {
			return errRes
		}
		return protocol.Success("permission", map[string]any{
			"tool":       tool.QualifiedName,
			"permission": tool.Permission,
		})
	}
	catalog, errRes, ok := l.loadCatalog(ctx, nil)
	if !ok {
		return errRes
	}
	items := make([]map[string]any, 0)
	for _, tool := range catalog.Tools {
		if server != "" && tool.ServerName != server {
			continue
		}
		items = append(items, map[string]any{
			"tool":       tool.QualifiedName,
			"permission": tool.Permission,
		})
	}
	return protocol.Success("permissions", map[string]any{"tools": items})
}

func (l *Live) status(ctx context.Context) protocol.ToolResult {
	catalog, errRes, ok := l.loadCatalog(ctx, nil)
	if !ok {
		return errRes
	}
	return protocol.Success("gateway status", map[string]any{
		"listedTools":     ListedTools(),
		"downstreamCount": len(catalog.Tools),
	})
}

func (l *Live) resolveTool(ctx context.Context, qualified string) (catalogTool, catalogServer, protocol.ToolResult, bool) {
	if !protocol.ValidQualifiedToolName(qualified) {
		return catalogTool{}, catalogServer{}, protocol.Fail(protocol.ErrorNotFound, unknownToolMessage, false), false
	}
	raw, _ := json.Marshal(map[string]any{"qualifiedName": qualified})
	catalog, errRes, ok := l.loadCatalog(ctx, raw)
	if !ok {
		return catalogTool{}, catalogServer{}, errRes, false
	}
	var tool catalogTool
	found := false
	for _, candidate := range catalog.Tools {
		if candidate.QualifiedName == qualified {
			tool = candidate
			found = true
			break
		}
	}
	if !found {
		return catalogTool{}, catalogServer{}, protocol.Fail(protocol.ErrorNotFound, unknownToolMessage, false), false
	}
	var server catalogServer
	for _, candidate := range catalog.Servers {
		if candidate.ID == tool.ServerID {
			server = candidate
			break
		}
	}
	if server.ID == "" || !server.Enabled || tool.Permission != string(protocol.GatewayAllow) {
		return catalogTool{}, catalogServer{}, protocol.Fail(protocol.ErrorNotFound, unknownToolMessage, false), false
	}
	return tool, server, protocol.ToolResult{}, true
}

func (l *Live) loadCatalog(ctx context.Context, input json.RawMessage) (catalogView, protocol.ToolResult, bool) {
	result := l.Runner.Call(ctx, protocol.OpMCPGatewayCatalog, input)
	if !result.OK {
		if result.Error != nil {
			return catalogView{}, result, false
		}
		return catalogView{}, protocol.Fail(protocol.ErrorUnavailable, "MCP gateway catalog is unavailable", true), false
	}
	raw, err := json.Marshal(result.Data)
	if err != nil {
		return catalogView{}, protocol.Fail(protocol.ErrorUnavailable, "MCP gateway catalog is unavailable", true), false
	}
	var view catalogView
	if err := json.Unmarshal(raw, &view); err != nil {
		return catalogView{}, protocol.Fail(protocol.ErrorUnavailable, "MCP gateway catalog is unavailable", true), false
	}
	return view, protocol.ToolResult{}, true
}

func (l *Live) credentials(ctx context.Context, serverID, toolName, purpose string) (credentialsView, protocol.ToolResult, bool) {
	payload, err := json.Marshal(map[string]any{
		"serverId": serverID,
		"toolName": toolName,
		"purpose":  purpose,
	})
	if err != nil {
		return credentialsView{}, protocol.Fail(protocol.ErrorInternal, "failed to encode credentials request", false), false
	}
	result := l.Runner.Call(ctx, protocol.OpMCPServerGetCredentials, payload)
	if !result.OK {
		if result.Error != nil {
			return credentialsView{}, result, false
		}
		return credentialsView{}, protocol.Fail(protocol.ErrorUnavailable, "MCP credentials are unavailable", true), false
	}
	raw, err := json.Marshal(result.Data)
	if err != nil {
		return credentialsView{}, protocol.Fail(protocol.ErrorUnavailable, "MCP credentials are unavailable", true), false
	}
	var view credentialsView
	if err := json.Unmarshal(raw, &view); err != nil {
		return credentialsView{}, protocol.Fail(protocol.ErrorUnavailable, "MCP credentials are unavailable", true), false
	}
	return view, protocol.ToolResult{}, true
}

func searchable(catalog catalogView) []catalogTool {
	enabled := map[string]bool{}
	for _, server := range catalog.Servers {
		if server.Enabled {
			enabled[server.ID] = true
		}
	}
	out := make([]catalogTool, 0)
	for _, tool := range catalog.Tools {
		if enabled[tool.ServerID] && tool.Permission == string(protocol.GatewayAllow) {
			out = append(out, tool)
		}
	}
	return out
}

func redactResult(result protocol.ToolResult, secrets []string) protocol.ToolResult {
	result.Message = sanitizeText(result.Message, secrets)
	if result.Error != nil {
		result.Error.Message = sanitizeText(result.Error.Message, secrets)
	}
	if result.Data != nil {
		result.Data = sanitizeValue(result.Data, secrets)
	}
	return result
}

func sanitizeValue(value any, secrets []string) any {
	switch typed := value.(type) {
	case string:
		return sanitizeText(typed, secrets)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = sanitizeValue(item, secrets)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = sanitizeValue(item, secrets)
		}
		return out
	default:
		return value
	}
}
