package mcpgw

import (
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

type traceInput struct {
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

type traceListInput struct {
	ServerID string `json:"serverId"`
	Limit    int    `json:"limit"`
	Cursor   string `json:"cursor"`
}

type traceRow struct {
	ID            string
	PrincipalID   string
	ServerID      sql.NullString
	ServerName    string
	Tool          sql.NullString
	Operation     string
	ClientID      sql.NullString
	DurationMs    int
	Status        string
	ErrorCode     sql.NullString
	ErrorMessage  sql.NullString
	RequestBytes  sql.NullInt64
	ResponseBytes sql.NullInt64
	CreatedAt     int64
}

func (s *Store) appendTrace(principal string, raw json.RawMessage) protocol.ToolResult {
	var in traceInput
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
	if in.ErrorMessage != nil {
		message = scrubStoredError(*in.ErrorMessage, in.Secrets)
	}
	id := protocol.NewOpaqueID(protocol.PrefixMCPTrace)
	now := time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO mcp_gateway_traces
		(id, principal_id, server_id, server_name, tool, operation, client_id, duration_ms, status,
		 error_code, error_message, request_bytes, response_bytes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, principal, nullPtr(in.ServerID), name, nullPtr(in.Tool), op, nullPtr(in.ClientID),
		in.DurationMs, status, nullPtr(in.ErrorCode), message, nullInt(in.RequestBytes), nullInt(in.ResponseBytes), now); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if _, err := tx.Exec(`DELETE FROM mcp_gateway_traces
		WHERE principal_id = ? AND rowid NOT IN (
			SELECT rowid FROM mcp_gateway_traces WHERE principal_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?
		)`, principal, principal, maxRows); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if err := tx.Commit(); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	view, err := s.loadTrace(id)
	if err != nil || view == nil {
		return protocol.Fail(protocol.ErrorInternal, "MCP trace did not persist", true)
	}
	return protocol.Success("MCP trace recorded", map[string]any{"trace": view})
}

func (s *Store) listTraces(principal string, raw json.RawMessage) protocol.ToolResult {
	var in traceListInput
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
	query := `SELECT id, principal_id, server_id, server_name, tool, operation, client_id, duration_ms, status,
		error_code, error_message, request_bytes, response_bytes, created_at
		FROM mcp_gateway_traces WHERE principal_id = ?`
	args := []any{principal}
	if in.ServerID != "" {
		query += ` AND server_id = ?`
		args = append(args, in.ServerID)
	}
	if cursor, ok := parseTraceCursor(in.Cursor); ok {
		query += ` AND (created_at < ? OR (created_at = ? AND id < ?))`
		args = append(args, cursor.createdAt, cursor.createdAt, cursor.id)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	defer rows.Close()
	traces := make([]map[string]any, 0)
	for rows.Next() {
		var rec traceRow
		if err := rows.Scan(&rec.ID, &rec.PrincipalID, &rec.ServerID, &rec.ServerName, &rec.Tool, &rec.Operation, &rec.ClientID, &rec.DurationMs, &rec.Status,
			&rec.ErrorCode, &rec.ErrorMessage, &rec.RequestBytes, &rec.ResponseBytes, &rec.CreatedAt); err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		traces = append(traces, traceView(rec))
	}
	if err := rows.Err(); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	res := protocol.Success("MCP traces listed", map[string]any{"traces": traces})
	if len(traces) == limit && limit > 0 {
		last := traces[len(traces)-1]
		res.Cursor = formatTraceCursor(asInt64(last["createdAt"]), last["id"].(string))
	}
	return res
}

func (s *Store) loadTrace(id string) (map[string]any, error) {
	row := s.db.QueryRow(`SELECT id, principal_id, server_id, server_name, tool, operation, client_id, duration_ms, status,
		error_code, error_message, request_bytes, response_bytes, created_at
		FROM mcp_gateway_traces WHERE id = ?`, id)
	var rec traceRow
	if err := row.Scan(&rec.ID, &rec.PrincipalID, &rec.ServerID, &rec.ServerName, &rec.Tool, &rec.Operation, &rec.ClientID, &rec.DurationMs, &rec.Status,
		&rec.ErrorCode, &rec.ErrorMessage, &rec.RequestBytes, &rec.ResponseBytes, &rec.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return traceView(rec), nil
}

func traceView(rec traceRow) map[string]any {
	return map[string]any{
		"id":            rec.ID,
		"principalId":   rec.PrincipalID,
		"serverId":      nullStr(rec.ServerID),
		"serverName":    rec.ServerName,
		"tool":          nullStr(rec.Tool),
		"operation":     rec.Operation,
		"clientId":      nullStr(rec.ClientID),
		"durationMs":    rec.DurationMs,
		"status":        rec.Status,
		"errorCode":     nullStr(rec.ErrorCode),
		"errorMessage":  nullStr(rec.ErrorMessage),
		"requestBytes":  nullInt64(rec.RequestBytes),
		"responseBytes": nullInt64(rec.ResponseBytes),
		"createdAt":     rec.CreatedAt,
	}
}

func formatTraceCursor(createdAt int64, id string) string {
	return strconv.FormatInt(createdAt, 10) + "." + id
}

func parseTraceCursor(cursor string) (struct {
	createdAt int64
	id        string
}, bool) {
	var out struct {
		createdAt int64
		id        string
	}
	sep := strings.IndexByte(cursor, '.')
	if sep <= 0 {
		return out, false
	}
	createdAt, err := strconv.ParseInt(cursor[:sep], 10, 64)
	if err != nil || createdAt <= 0 {
		return out, false
	}
	id := cursor[sep+1:]
	if id == "" {
		return out, false
	}
	out.createdAt = createdAt
	out.id = id
	return out, true
}

func nullPtr(v *string) any {
	if v == nil {
		return nil
	}
	s := strings.TrimSpace(*v)
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullStr(v sql.NullString) any {
	if !v.Valid || v.String == "" {
		return nil
	}
	return v.String
}

func nullInt64(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func asInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	default:
		return 0
	}
}
