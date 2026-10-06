package mcpgw

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

// Store is the durable MCP-gateway registry (today apps/runner mcp-gateway-store).
// secretRef is stored but never resolved here. Trace writes scrub secrets and
// never persist arguments, results, or credential values.
type Store struct {
	db *sql.DB
}

type header struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	SecretRef string `json:"secretRef,omitempty"`
}

type serverRow struct {
	ID                string
	PrincipalID       string
	Name              string
	Description       string
	Transport         string
	Endpoint          string
	HeadersJSON       string
	Enabled           int
	Status            string
	ToolCount         int
	LastConnectedAt   sql.NullInt64
	LastError         sql.NullString
	LastCheckedAt     sql.NullInt64
	PermissionDefault string
	Generation        int
	CreatedAt         int64
	UpdatedAt         int64
}

type toolRow struct {
	ID            string
	PrincipalID   string
	ServerID      string
	ServerName    string
	UpstreamName  string
	QualifiedName string
	Description   string
	SchemaJSON    string
	Annotations   sql.NullString
	Availability  string
	DiscoveredAt  int64
	Permission    string
}

// Open creates the MCP-gateway schema.
func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("mcp gateway store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS mcp_gateway_servers (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  transport TEXT NOT NULL CHECK (transport IN ('streamable-http', 'sse')),
  endpoint TEXT NOT NULL,
  headers_json TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  status TEXT NOT NULL CHECK (status IN ('unknown', 'connected', 'connecting', 'disconnected', 'error', 'disabled')),
  tool_count INTEGER NOT NULL DEFAULT 0,
  last_connected_at INTEGER,
  last_error TEXT,
  last_checked_at INTEGER,
  permission_default TEXT NOT NULL CHECK (permission_default IN ('allow', 'deny')),
  state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'DELETED')),
  generation INTEGER NOT NULL CHECK (generation > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER,
  UNIQUE(principal_id, name)
);
CREATE INDEX IF NOT EXISTS mcp_servers_principal_updated ON mcp_gateway_servers(principal_id, updated_at DESC, id);

CREATE TABLE IF NOT EXISTS mcp_gateway_tools (
  id TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL,
  server_id TEXT NOT NULL,
  upstream_name TEXT NOT NULL,
  qualified_name TEXT NOT NULL,
  description TEXT NOT NULL,
  input_schema_json TEXT NOT NULL,
  schema_bytes INTEGER NOT NULL DEFAULT 0,
  annotations_json TEXT,
  availability TEXT NOT NULL CHECK (availability IN ('available', 'unavailable')),
  discovered_at INTEGER NOT NULL,
  PRIMARY KEY(principal_id, server_id, upstream_name),
  UNIQUE(principal_id, qualified_name)
);
CREATE INDEX IF NOT EXISTS mcp_tools_principal_server ON mcp_gateway_tools(principal_id, server_id);

CREATE TABLE IF NOT EXISTS mcp_gateway_tool_permissions (
  principal_id TEXT NOT NULL,
  server_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  permission TEXT NOT NULL CHECK (permission IN ('allow', 'deny')),
  PRIMARY KEY(principal_id, server_id, tool_name)
);

CREATE TABLE IF NOT EXISTS mcp_gateway_traces (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  server_id TEXT,
  server_name TEXT NOT NULL,
  tool TEXT,
  operation TEXT NOT NULL,
  client_id TEXT,
  duration_ms INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('success', 'error', 'denied')),
  error_code TEXT,
  error_message TEXT,
  request_bytes INTEGER,
  response_bytes INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mcp_traces_principal_created ON mcp_gateway_traces(principal_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS mcp_traces_principal_server ON mcp_gateway_traces(principal_id, server_id, created_at DESC);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Handle dispatches one internal MCP-gateway RPC.
func (s *Store) Handle(req protocol.RunnerRequest) protocol.ToolResult {
	principal := strings.TrimSpace(req.OwnerID)
	if principal == "" {
		principal = "owner"
	}
	switch req.Operation {
	case protocol.OpMCPGatewayCatalog:
		return s.catalog(principal, req.Input)
	case protocol.OpMCPServerGetCredentials:
		return s.credentials(principal, req.Input)
	case protocol.OpMCPServerCreate:
		return s.create(principal, req.Input)
	case protocol.OpMCPServerReplaceTools:
		return s.replaceTools(principal, req.Input)
	case protocol.OpMCPServerSetPermissions:
		return s.setPermissions(principal, req.Input)
	case protocol.OpMCPServerConnectionResult:
		return s.recordConnectionResult(principal, req.Input)
	case protocol.OpMCPGatewayTraceAppend:
		return s.appendTrace(principal, req.Input)
	case protocol.OpMCPGatewayTraceList:
		return s.listTraces(principal, req.Input)
	case protocol.OpMCPServerList:
		return s.list(principal, req.Input)
	case protocol.OpMCPServerGet:
		return s.get(principal, req.Input)
	case protocol.OpMCPServerUpdate:
		return s.update(principal, req.Input)
	case protocol.OpMCPServerDelete:
		return s.delete(principal, req.Input)
	case protocol.OpMCPServerSetEnabled:
		return s.setEnabled(principal, req.Input)
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

type connectionResultInput struct {
	ServerID string  `json:"serverId"`
	Status   string  `json:"status"`
	Error    *string `json:"error"`
}

type setPermissionsInput struct {
	ServerID           string `json:"serverId"`
	PermissionDefault  string `json:"permissionDefault"`
	ExpectedGeneration int    `json:"expectedGeneration"`
	Tools              []struct {
		Name       string `json:"name"`
		Permission string `json:"permission"`
	} `json:"tools"`
}

func (s *Store) catalog(principal string, raw json.RawMessage) protocol.ToolResult {
	var filter catalogFilter
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &filter); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid catalog filter", false)
		}
	}
	servers, err := s.listServers(principal, filter.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	var tools []map[string]any
	if filter.QualifiedName != "" {
		tool, err := s.getTool(principal, filter.QualifiedName)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		if tool != nil {
			tools = []map[string]any{tool}
		} else {
			tools = []map[string]any{}
		}
	} else {
		listed, err := s.listTools(principal, filter.ServerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		tools = listed
	}
	return protocol.Success("MCP gateway catalog", map[string]any{"servers": servers, "tools": tools})
}

func (s *Store) create(principal string, raw json.RawMessage) protocol.ToolResult {
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
	headers, errMsg := parseCreateHeaders(in.Headers)
	if errMsg != "" {
		return protocol.Fail(protocol.ErrorInvalidInput, errMsg, false)
	}
	if transport == string(protocol.GatewayTransportSSE) {
		for _, header := range headers {
			if header.SecretRef != "" {
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
	status := "unknown"
	if !enabled {
		status = "disabled"
	}
	now := time.Now().UnixMilli()
	id := protocol.NewOpaqueID(protocol.PrefixMCPServer)
	headerJSON, _ := json.Marshal(headers)
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := s.db.Exec(`INSERT INTO mcp_gateway_servers
		(id, principal_id, name, description, transport, endpoint, headers_json, enabled, status, tool_count,
		 last_connected_at, last_error, last_checked_at, permission_default, state, generation, created_at, updated_at, deleted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, ?, 'ACTIVE', 1, ?, ?, NULL)`,
		id, principal, name, nullIfEmpty(in.Description), transport, endpoint, string(headerJSON), enabledInt, status, string(perm), now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return protocol.Fail(protocol.ErrorConflict, "MCP server name already exists", false)
		}
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	rec, err := s.loadServer(principal, id)
	if err != nil || rec == nil {
		return protocol.Fail(protocol.ErrorInternal, "MCP server create did not persist", true)
	}
	return protocol.Success("MCP server created", serverView(*rec, 0, nil))
}

func (s *Store) replaceTools(principal string, raw json.RawMessage) protocol.ToolResult {
	var in replaceToolsInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid replace tools input", false)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, in.ServerID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "serverId is required", false)
	}
	capN := in.Cap
	if capN <= 0 {
		capN = 500
	}
	status := strings.TrimSpace(in.Status)
	if status == "" {
		status = "connected"
	}
	rec, err := s.loadServer(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if rec == nil {
		return protocol.Fail(protocol.ErrorNotFound, "MCP server is unavailable", false)
	}
	now := time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM mcp_gateway_tools WHERE principal_id = ? AND server_id = ?`, principal, in.ServerID); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	insert, err := tx.Prepare(`INSERT INTO mcp_gateway_tools
		(id, principal_id, server_id, upstream_name, qualified_name, description, input_schema_json, schema_bytes,
		 annotations_json, availability, discovered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	defer insert.Close()
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
		if i >= capN {
			availability = "unavailable"
			desc = "tool omitted: per-server tool limit reached"
		}
		schema := tool.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		schemaJSON, _ := json.Marshal(schema)
		var ann any
		if tool.Annotations != nil {
			rawAnn, _ := json.Marshal(tool.Annotations)
			ann = string(rawAnn)
		}
		if _, err := insert.Exec(protocol.NewOpaqueID(protocol.PrefixMCPTool), principal, in.ServerID, name,
			protocol.QualifiedToolName(rec.Name, name), desc, string(schemaJSON), len(schemaJSON), ann, availability, now); err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
	}
	lastErr := rec.LastError
	if status == "connected" {
		lastErr = sql.NullString{}
	}
	if _, err := tx.Exec(`UPDATE mcp_gateway_servers
		SET tool_count = ?, status = ?, last_error = ?, last_checked_at = ?,
		    last_connected_at = CASE WHEN ? = 'connected' THEN ? ELSE last_connected_at END,
		    updated_at = ?
		WHERE principal_id = ? AND id = ? AND state = 'ACTIVE'`,
		len(in.Tools), status, nullString(lastErr), now, status, now, now, principal, in.ServerID); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if err := tx.Commit(); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	tools, err := s.listTools(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	return protocol.Success("MCP tools replaced", map[string]any{"tools": tools, "toolCount": len(in.Tools)})
}

func validGatewayStatus(status string) bool {
	switch status {
	case "unknown", "connected", "connecting", "disconnected", "error", "disabled":
		return true
	default:
		return false
	}
}

func (s *Store) recordConnectionResult(principal string, raw json.RawMessage) protocol.ToolResult {
	var in connectionResultInput
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
	rec, err := s.loadServer(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if rec == nil {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	now := time.Now().UnixMilli()
	var lastErr any
	if in.Error != nil && strings.TrimSpace(*in.Error) != "" {
		lastErr = scrubStoredError(*in.Error, nil)
	}
	if _, err := s.db.Exec(`UPDATE mcp_gateway_servers
		SET status = ?, last_error = ?, last_checked_at = ?,
		    last_connected_at = CASE WHEN ? = 'connected' THEN ? ELSE last_connected_at END,
		    updated_at = ?
		WHERE principal_id = ? AND id = ? AND state = 'ACTIVE'`,
		status, lastErr, now, status, now, now, principal, in.ServerID); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	updated, err := s.loadServer(principal, in.ServerID)
	if err != nil || updated == nil {
		return protocol.Fail(protocol.ErrorInternal, "MCP connection result did not persist", true)
	}
	count, _ := s.toolCount(principal, in.ServerID)
	return protocol.Success("MCP connection result recorded", serverView(*updated, count, nil))
}

func (s *Store) setPermissions(principal string, raw json.RawMessage) protocol.ToolResult {
	var in setPermissionsInput
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
	rec, err := s.loadServer(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if rec == nil {
		return protocol.Fail(protocol.ErrorNotFound, "MCP server is unavailable", false)
	}
	if rec.Generation != in.ExpectedGeneration {
		return protocol.Fail(protocol.ErrorConflict, "stale MCP server generation", false)
	}
	now := time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM mcp_gateway_tool_permissions WHERE principal_id = ? AND server_id = ?`, principal, in.ServerID); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	insert, err := tx.Prepare(`INSERT INTO mcp_gateway_tool_permissions (principal_id, server_id, tool_name, permission) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	defer insert.Close()
	for _, tool := range in.Tools {
		name := strings.TrimSpace(tool.Name)
		if !validToolName(name) {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid upstream tool name", false)
		}
		p := protocol.GatewayPermission(strings.TrimSpace(tool.Permission))
		if p != protocol.GatewayAllow && p != protocol.GatewayDeny {
			return protocol.Fail(protocol.ErrorInvalidInput, "permission must be allow or deny", false)
		}
		if _, err := insert.Exec(principal, in.ServerID, name, string(p)); err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
	}
	res, err := tx.Exec(`UPDATE mcp_gateway_servers
		SET permission_default = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		string(perm), now, principal, in.ServerID, in.ExpectedGeneration)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return protocol.Fail(protocol.ErrorConflict, "stale MCP server generation", false)
	}
	if err := tx.Commit(); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	updated, err := s.loadServer(principal, in.ServerID)
	if err != nil || updated == nil {
		return protocol.Fail(protocol.ErrorInternal, "MCP permissions did not persist", true)
	}
	count, _ := s.toolCount(principal, in.ServerID)
	return protocol.Success("MCP permissions updated", serverView(*updated, count, nil))
}

func (s *Store) credentials(principal string, raw json.RawMessage) protocol.ToolResult {
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
	rec, err := s.loadServer(principal, in.ServerID)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if rec == nil {
		return protocol.Fail(protocol.ErrorNotFound, "MCP server is unavailable", false)
	}
	if rec.Enabled == 0 {
		return protocol.Success("MCP server is disabled", map[string]any{"allowed": false, "reason": "server_disabled"})
	}
	if in.Purpose == "execute" {
		perm := s.effectivePermission(principal, rec.ID, rec.PermissionDefault, in.ToolName)
		if in.ToolName == "" || perm != string(protocol.GatewayAllow) {
			return protocol.Success("MCP tool access denied", map[string]any{"allowed": false, "reason": "tool_denied"})
		}
		if !s.toolExists(principal, rec.ID, in.ToolName) {
			return protocol.Success("MCP tool access denied", map[string]any{"allowed": false, "reason": "tool_denied"})
		}
	}
	var headers []header
	if err := json.Unmarshal([]byte(rec.HeadersJSON), &headers); err != nil {
		return protocol.Fail(protocol.ErrorInternal, "stored headers are unreadable", true)
	}
	resolved := map[string]string{}
	for _, header := range headers {
		if header.SecretRef != "" {
			return protocol.Fail(protocol.ErrorNotFound, "referenced secret "+header.SecretRef+" is unavailable", false)
		}
		if header.Value != "" {
			resolved[header.Name] = header.Value
		}
	}
	return protocol.Success("MCP credentials resolved", map[string]any{
		"allowed":   true,
		"transport": rec.Transport,
		"endpoint":  rec.Endpoint,
		"headers":   resolved,
	})
}

func (s *Store) loadServer(principal, id string) (*serverRow, error) {
	row := s.db.QueryRow(`SELECT id, principal_id, name, COALESCE(description,''), transport, endpoint, headers_json, enabled, status, tool_count,
		last_connected_at, last_error, last_checked_at, permission_default, generation, created_at, updated_at
		FROM mcp_gateway_servers WHERE principal_id = ? AND id = ? AND state = 'ACTIVE'`, principal, id)
	var rec serverRow
	if err := row.Scan(&rec.ID, &rec.PrincipalID, &rec.Name, &rec.Description, &rec.Transport, &rec.Endpoint, &rec.HeadersJSON, &rec.Enabled, &rec.Status, &rec.ToolCount,
		&rec.LastConnectedAt, &rec.LastError, &rec.LastCheckedAt, &rec.PermissionDefault, &rec.Generation, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &rec, nil
}

func (s *Store) listServers(principal, serverID string) ([]map[string]any, error) {
	query := `SELECT id, principal_id, name, COALESCE(description,''), transport, endpoint, headers_json, enabled, status, tool_count,
		last_connected_at, last_error, last_checked_at, permission_default, generation, created_at, updated_at
		FROM mcp_gateway_servers WHERE principal_id = ? AND state = 'ACTIVE'`
	args := []any{principal}
	if serverID != "" {
		query += ` AND id = ?`
		args = append(args, serverID)
	}
	query += ` ORDER BY updated_at DESC, id`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var rec serverRow
		if err := rows.Scan(&rec.ID, &rec.PrincipalID, &rec.Name, &rec.Description, &rec.Transport, &rec.Endpoint, &rec.HeadersJSON, &rec.Enabled, &rec.Status, &rec.ToolCount,
			&rec.LastConnectedAt, &rec.LastError, &rec.LastCheckedAt, &rec.PermissionDefault, &rec.Generation, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, serverView(rec, rec.ToolCount, parseHeaders(rec.HeadersJSON)))
	}
	return out, rows.Err()
}

func (s *Store) listTools(principal, serverID string) ([]map[string]any, error) {
	query := `SELECT t.id, t.principal_id, t.server_id, s.name, t.upstream_name, t.qualified_name, t.description, t.input_schema_json, t.annotations_json, t.availability, t.discovered_at
		FROM mcp_gateway_tools t JOIN mcp_gateway_servers s ON s.id = t.server_id AND s.principal_id = t.principal_id
		WHERE t.principal_id = ? AND s.state = 'ACTIVE'`
	args := []any{principal}
	if serverID != "" {
		query += ` AND t.server_id = ?`
		args = append(args, serverID)
	}
	query += ` ORDER BY t.qualified_name`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	defaults, overrides, err := s.permissionMaps(principal)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0)
	for rows.Next() {
		var rec toolRow
		if err := rows.Scan(&rec.ID, &rec.PrincipalID, &rec.ServerID, &rec.ServerName, &rec.UpstreamName, &rec.QualifiedName, &rec.Description, &rec.SchemaJSON, &rec.Annotations, &rec.Availability, &rec.DiscoveredAt); err != nil {
			return nil, err
		}
		rec.Permission = decide(rec.ServerID, rec.UpstreamName, overrides, defaults)
		out = append(out, toolView(rec))
	}
	return out, rows.Err()
}

func (s *Store) getTool(principal, qualified string) (map[string]any, error) {
	row := s.db.QueryRow(`SELECT t.id, t.principal_id, t.server_id, s.name, t.upstream_name, t.qualified_name, t.description, t.input_schema_json, t.annotations_json, t.availability, t.discovered_at
		FROM mcp_gateway_tools t JOIN mcp_gateway_servers s ON s.id = t.server_id AND s.principal_id = t.principal_id
		WHERE t.principal_id = ? AND t.qualified_name = ? AND s.state = 'ACTIVE'`, principal, qualified)
	var rec toolRow
	if err := row.Scan(&rec.ID, &rec.PrincipalID, &rec.ServerID, &rec.ServerName, &rec.UpstreamName, &rec.QualifiedName, &rec.Description, &rec.SchemaJSON, &rec.Annotations, &rec.Availability, &rec.DiscoveredAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	rec.Permission = s.effectivePermission(principal, rec.ServerID, "", rec.UpstreamName)
	if rec.Permission == "" {
		rec.Permission = string(protocol.GatewayDeny)
	}
	return toolView(rec), nil
}

func (s *Store) toolExists(principal, serverID, upstream string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(1) FROM mcp_gateway_tools WHERE principal_id = ? AND server_id = ? AND upstream_name = ?`, principal, serverID, upstream).Scan(&n)
	return n > 0
}

func (s *Store) toolCount(principal, serverID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM mcp_gateway_tools WHERE principal_id = ? AND server_id = ?`, principal, serverID).Scan(&n)
	return n, err
}

func (s *Store) effectivePermission(principal, serverID, fallback, toolName string) string {
	var override string
	err := s.db.QueryRow(`SELECT permission FROM mcp_gateway_tool_permissions WHERE principal_id = ? AND server_id = ? AND tool_name = ?`, principal, serverID, toolName).Scan(&override)
	if err == nil {
		return override
	}
	if fallback != "" {
		return fallback
	}
	var def string
	_ = s.db.QueryRow(`SELECT permission_default FROM mcp_gateway_servers WHERE principal_id = ? AND id = ? AND state = 'ACTIVE'`, principal, serverID).Scan(&def)
	if def == "" {
		return string(protocol.GatewayDeny)
	}
	return def
}

func (s *Store) permissionMaps(principal string) (map[string]string, map[string]string, error) {
	defaults := map[string]string{}
	rows, err := s.db.Query(`SELECT id, permission_default FROM mcp_gateway_servers WHERE principal_id = ? AND state = 'ACTIVE'`, principal)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, perm string
		if err := rows.Scan(&id, &perm); err != nil {
			return nil, nil, err
		}
		defaults[id] = perm
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	overrides := map[string]string{}
	orows, err := s.db.Query(`SELECT server_id, tool_name, permission FROM mcp_gateway_tool_permissions WHERE principal_id = ?`, principal)
	if err != nil {
		return nil, nil, err
	}
	defer orows.Close()
	for orows.Next() {
		var serverID, tool, perm string
		if err := orows.Scan(&serverID, &tool, &perm); err != nil {
			return nil, nil, err
		}
		overrides[serverID+"\x00"+tool] = perm
	}
	return defaults, overrides, orows.Err()
}

func decide(serverID, tool string, overrides, def map[string]string) string {
	if perm, ok := overrides[serverID+"\x00"+tool]; ok {
		return perm
	}
	if perm, ok := def[serverID]; ok && perm != "" {
		return perm
	}
	return string(protocol.GatewayDeny)
}

func parseCreateHeaders(in []createHeader) ([]header, string) {
	out := make([]header, 0, len(in))
	for _, item := range in {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, "header name is required"
		}
		if len(item.Value) == 0 {
			return nil, "header value is required"
		}
		var literal string
		if err := json.Unmarshal(item.Value, &literal); err == nil {
			out = append(out, header{Name: name, Value: literal})
			continue
		}
		var ref struct {
			SecretRef string `json:"secretRef"`
		}
		if err := json.Unmarshal(item.Value, &ref); err != nil || strings.TrimSpace(ref.SecretRef) == "" {
			return nil, "header value must be a literal or secretRef"
		}
		out = append(out, header{Name: name, SecretRef: strings.TrimSpace(ref.SecretRef)})
	}
	return out, ""
}

func parseHeaders(raw string) []header {
	var out []header
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func serverView(rec serverRow, toolCount int, headers []header) map[string]any {
	if headers == nil {
		headers = parseHeaders(rec.HeadersJSON)
	}
	items := make([]map[string]any, 0, len(headers))
	for _, header := range headers {
		item := map[string]any{"name": header.Name}
		if header.SecretRef != "" {
			item["kind"] = "secret"
			item["secretRef"] = header.SecretRef
		} else {
			item["kind"] = "literal"
			item["value"] = header.Value
		}
		items = append(items, item)
	}
	if toolCount == 0 {
		toolCount = rec.ToolCount
	}
	return map[string]any{
		"id":                rec.ID,
		"principalId":       rec.PrincipalID,
		"name":              rec.Name,
		"description":       nilString(rec.Description),
		"transport":         rec.Transport,
		"endpoint":          rec.Endpoint,
		"headers":           items,
		"enabled":           rec.Enabled == 1,
		"status":            rec.Status,
		"toolCount":         toolCount,
		"lastConnectedAt":   nilUnix(rec.LastConnectedAt),
		"lastError":         nilNullString(rec.LastError),
		"lastCheckedAt":     nilUnix(rec.LastCheckedAt),
		"permissionDefault": rec.PermissionDefault,
		"generation":        rec.Generation,
		"createdAt":         rec.CreatedAt,
		"updatedAt":         rec.UpdatedAt,
	}
}

func toolView(rec toolRow) map[string]any {
	var schema any
	if err := json.Unmarshal([]byte(rec.SchemaJSON), &schema); err != nil || schema == nil {
		schema = map[string]any{"type": "object"}
	}
	var annotations any
	if rec.Annotations.Valid && rec.Annotations.String != "" {
		_ = json.Unmarshal([]byte(rec.Annotations.String), &annotations)
	}
	return map[string]any{
		"id":            rec.ID,
		"principalId":   rec.PrincipalID,
		"serverId":      rec.ServerID,
		"serverName":    rec.ServerName,
		"qualifiedName": rec.QualifiedName,
		"upstreamName":  rec.UpstreamName,
		"description":   rec.Description,
		"inputSchema":   schema,
		"annotations":   annotations,
		"availability":  rec.Availability,
		"permission":    rec.Permission,
		"discoveredAt":  rec.DiscoveredAt,
	}
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

func nilString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nilNullString(v sql.NullString) any {
	if !v.Valid || v.String == "" {
		return nil
	}
	return v.String
}

func nilUnix(v sql.NullInt64) any {
	if !v.Valid || v.Int64 <= 0 {
		return nil
	}
	return v.Int64
}

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullString(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}
