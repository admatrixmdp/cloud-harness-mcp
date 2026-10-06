package mcpgw

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

type serverIDInput struct {
	ServerID           string `json:"serverId"`
	ExpectedGeneration int    `json:"expectedGeneration"`
}

type setEnabledInput struct {
	ServerID           string `json:"serverId"`
	Enabled            bool   `json:"enabled"`
	ExpectedGeneration int    `json:"expectedGeneration"`
}

func (s *Store) list(principal string, _ json.RawMessage) protocol.ToolResult {
	servers, err := s.listServers(principal, "")
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	return protocol.Success("MCP servers listed", map[string]any{"servers": servers})
}

func (s *Store) get(principal string, raw json.RawMessage) protocol.ToolResult {
	var in serverIDInput
	if err := json.Unmarshal(raw, &in); err != nil || !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	rec, err := s.loadServer(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if rec == nil {
		return protocol.Fail(protocol.ErrorNotFound, "MCP server not found", false)
	}
	tools, err := s.listTools(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	return protocol.Success("MCP server retrieved", map[string]any{
		"server": serverView(*rec, rec.ToolCount, nil),
		"tools":  tools,
	})
}

func (s *Store) update(principal string, raw json.RawMessage) protocol.ToolResult {
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
	rec, err := s.loadServer(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if rec == nil || rec.Generation != in.ExpectedGeneration {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	name := rec.Name
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
		if !validServerName(name) {
			return protocol.Fail(protocol.ErrorInvalidInput, "server name must be 1-63 lowercase letters, numbers, or hyphens", false)
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
	headers := parseHeaders(rec.HeadersJSON)
	if in.Headers != nil {
		parsed, errMsg := parseCreateHeaders(in.Headers)
		if errMsg != "" {
			return protocol.Fail(protocol.ErrorInvalidInput, errMsg, false)
		}
		headers = parsed
	}
	if transport == string(protocol.GatewayTransportSSE) {
		for _, header := range headers {
			if header.SecretRef != "" {
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
		perm = string(next)
	}
	now := time.Now().UnixMilli()
	headerJSON, _ := json.Marshal(headers)
	tx, err := s.db.Begin()
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE mcp_gateway_servers
		SET name = ?, description = ?, transport = ?, endpoint = ?, headers_json = ?, permission_default = ?,
		    generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		name, nullIfEmpty(description), transport, endpoint, string(headerJSON), perm, now, principal, in.ServerID, in.ExpectedGeneration)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return protocol.Fail(protocol.ErrorConflict, "MCP server name already exists", false)
		}
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	if name != rec.Name {
		if _, err := tx.Exec(`UPDATE mcp_gateway_tools SET qualified_name = ? || '.' || upstream_name WHERE principal_id = ? AND server_id = ?`,
			name, principal, in.ServerID); err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
	}
	if err := tx.Commit(); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	updated, err := s.loadServer(principal, in.ServerID)
	if err != nil || updated == nil {
		return protocol.Fail(protocol.ErrorInternal, "MCP server update did not persist", true)
	}
	count, _ := s.toolCount(principal, in.ServerID)
	return protocol.Success("MCP server updated", serverView(*updated, count, nil))
}

func (s *Store) setEnabled(principal string, raw json.RawMessage) protocol.ToolResult {
	var in setEnabledInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid MCP server enabled input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	rec, err := s.loadServer(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if rec == nil || rec.Generation != in.ExpectedGeneration {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	status := rec.Status
	if in.Enabled {
		if status == "disabled" {
			status = "unknown"
		}
	} else {
		status = "disabled"
	}
	enabledInt := 0
	if in.Enabled {
		enabledInt = 1
	}
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`UPDATE mcp_gateway_servers
		SET enabled = ?, status = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		enabledInt, status, now, principal, in.ServerID, in.ExpectedGeneration)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	updated, err := s.loadServer(principal, in.ServerID)
	if err != nil || updated == nil {
		return protocol.Fail(protocol.ErrorInternal, "MCP server enabled update did not persist", true)
	}
	count, _ := s.toolCount(principal, in.ServerID)
	message := "MCP server disabled"
	if in.Enabled {
		message = "MCP server enabled"
	}
	return protocol.Success(message, serverView(*updated, count, nil))
}

func (s *Store) delete(principal string, raw json.RawMessage) protocol.ToolResult {
	var in serverIDInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid MCP server delete input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	rec, err := s.loadServer(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if rec == nil || rec.Generation != in.ExpectedGeneration {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	now := time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE mcp_gateway_servers
		SET state = 'DELETED', enabled = 0, status = 'disabled', generation = generation + 1, updated_at = ?, deleted_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		now, now, principal, in.ServerID, in.ExpectedGeneration)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	if _, err := tx.Exec(`DELETE FROM mcp_gateway_tools WHERE principal_id = ? AND server_id = ?`, principal, in.ServerID); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if _, err := tx.Exec(`DELETE FROM mcp_gateway_tool_permissions WHERE principal_id = ? AND server_id = ?`, principal, in.ServerID); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if _, err := tx.Exec(`DELETE FROM mcp_gateway_traces WHERE principal_id = ? AND server_id = ?`, principal, in.ServerID); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if err := tx.Commit(); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	rec.Enabled = 0
	rec.Status = "disabled"
	rec.Generation++
	rec.UpdatedAt = now
	rec.ToolCount = 0
	return protocol.Success("MCP server deleted", serverView(*rec, 0, nil))
}
