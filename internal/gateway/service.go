package gateway

import (
	"context"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// DownstreamTool is a cached catalog row. It is never returned from tools/list.
type DownstreamTool struct {
	Server      string
	Name        string
	Description string
	InputSchema map[string]any
	Permission  protocol.GatewayPermission
}

// Qualified is server.name.
func (t DownstreamTool) Qualified() string {
	return protocol.QualifiedToolName(t.Server, t.Name)
}

// Registry is an in-process catalog used until the runner store is wired.
type Registry struct {
	tools  []DownstreamTool
	Client *DownstreamClient
}

// NewRegistry constructs a catalog. Downstream tools stay off tools/list.
func NewRegistry(tools ...DownstreamTool) *Registry {
	return &Registry{tools: tools}
}

// ListedTools is the constant five-tool surface.
func ListedTools() []string {
	return append([]string{}, protocol.GatewayTools...)
}

// Search returns qualified matches. Secrets are never included.
func (r *Registry) Search(query, server string, limit int) protocol.ToolResult {
	if strings.TrimSpace(query) == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "query is required", false)
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 25 {
		limit = 25
	}
	q := strings.ToLower(query)
	matches := make([]map[string]any, 0)
	for _, tool := range r.tools {
		if server != "" && tool.Server != server {
			continue
		}
		haystack := strings.ToLower(tool.Qualified() + " " + tool.Description)
		if !strings.Contains(haystack, q) && !strings.Contains(haystack, strings.ToLower(tool.Name)) {
			continue
		}
		matches = append(matches, map[string]any{
			"tool":        tool.Qualified(),
			"description": tool.Description,
			"permission":  string(effective(tool.Permission)),
		})
		if len(matches) >= limit {
			break
		}
	}
	return protocol.Success("search results", map[string]any{"tools": matches})
}

// Inspect returns one tool schema.
func (r *Registry) Inspect(qualified string) protocol.ToolResult {
	tool, ok := r.lookup(qualified)
	if !ok {
		return protocol.Fail(protocol.ErrorNotFound, "unknown gateway tool", false)
	}
	schema := tool.InputSchema
	if schema == nil {
		schema = map[string]any{"type": "object"}
	}
	return protocol.Success("tool schema", map[string]any{
		"tool":        tool.Qualified(),
		"description": tool.Description,
		"inputSchema": schema,
		"permission":  string(effective(tool.Permission)),
	})
}

// Execute runs a permitted downstream tool. Denied tools fail closed and
// secrets are never echoed. Allowed tools post tools/call to the pinned
// endpoint when a DownstreamClient is configured.
func (r *Registry) Execute(qualified string, arguments map[string]any) protocol.ToolResult {
	tool, ok := r.lookup(qualified)
	if !ok {
		return protocol.Fail(protocol.ErrorNotFound, "unknown gateway tool", false)
	}
	if effective(tool.Permission) != protocol.GatewayAllow {
		return protocol.Fail(protocol.ErrorForbidden, "tool is denied by gateway policy", false)
	}
	if r.Client == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "downstream MCP execute is not wired in this Go-port slice", true)
	}
	return r.Client.Call(context.Background(), tool.Name, arguments)
}

// Permissions returns the effective decision.
func (r *Registry) Permissions(qualified, server string) protocol.ToolResult {
	if qualified != "" {
		tool, ok := r.lookup(qualified)
		if !ok {
			return protocol.Fail(protocol.ErrorNotFound, "unknown gateway tool", false)
		}
		return protocol.Success("permission", map[string]any{
			"tool":       tool.Qualified(),
			"permission": string(effective(tool.Permission)),
		})
	}
	items := make([]map[string]any, 0)
	for _, tool := range r.tools {
		if server != "" && tool.Server != server {
			continue
		}
		items = append(items, map[string]any{
			"tool":       tool.Qualified(),
			"permission": string(effective(tool.Permission)),
		})
	}
	return protocol.Success("permissions", map[string]any{"tools": items})
}

// Status is a process-local gateway heartbeat.
func (r *Registry) Status() protocol.ToolResult {
	return protocol.Success("gateway status", map[string]any{
		"listedTools":     ListedTools(),
		"downstreamCount": len(r.tools),
	})
}

func (r *Registry) lookup(qualified string) (DownstreamTool, bool) {
	if !protocol.ValidQualifiedToolName(qualified) {
		return DownstreamTool{}, false
	}
	for _, tool := range r.tools {
		if tool.Qualified() == qualified {
			return tool, true
		}
	}
	return DownstreamTool{}, false
}

func effective(p protocol.GatewayPermission) protocol.GatewayPermission {
	if p == protocol.GatewayAllow {
		return protocol.GatewayAllow
	}
	return protocol.GatewayDeny
}

// Dispatch handles one of the five meta-tools.
func (r *Registry) Dispatch(name string, input map[string]any) protocol.ToolResult {
	switch name {
	case protocol.GatewayToolSearch:
		query, _ := input["query"].(string)
		server, _ := input["server"].(string)
		limit := 5
		if n, ok := input["limit"].(float64); ok {
			limit = int(n)
		}
		return r.Search(query, server, limit)
	case protocol.GatewayToolInspect:
		tool, _ := input["tool"].(string)
		return r.Inspect(tool)
	case protocol.GatewayToolExecute:
		tool, _ := input["tool"].(string)
		args, _ := input["arguments"].(map[string]any)
		return r.Execute(tool, args)
	case protocol.GatewayToolPermissions:
		tool, _ := input["tool"].(string)
		server, _ := input["server"].(string)
		return r.Permissions(tool, server)
	case protocol.GatewayToolStatus:
		return r.Status()
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown gateway tool", false)
	}
}
