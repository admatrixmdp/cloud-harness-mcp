package grants

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

const (
	StatusPending  = "PENDING"
	StatusApproved = "APPROVED"
	StatusRejected = "REJECTED"
	StatusConsumed = "CONSUMED"
	StatusExpired  = "EXPIRED"
)

// Grant is an owner privilege grant for a bound command digest.
type Grant struct {
	ID            string
	OwnerID       string
	WorkspaceID   string
	Command       string
	Cwd           string
	CommandSHA256 string
	Status        string
	CreatedAt     int64
	ExpiresAt     int64
	ConsumedAt    int64
}

func (g Grant) PublicJSON() map[string]any {
	out := map[string]any{
		"id":            g.ID,
		"ownerId":       g.OwnerID,
		"workspaceId":   g.WorkspaceID,
		"command":       g.Command,
		"cwd":           g.Cwd,
		"commandSha256": g.CommandSHA256,
		"status":        g.Status,
		"createdAt":     g.CreatedAt,
		"expiresAt":     g.ExpiresAt,
	}
	if g.ConsumedAt > 0 {
		out["consumedAt"] = g.ConsumedAt
	} else {
		out["consumedAt"] = nil
	}
	return out
}

func (g Grant) RequestJSON() map[string]any {
	return map[string]any{
		"grantId":       g.ID,
		"workspaceId":   g.WorkspaceID,
		"commandSha256": g.CommandSHA256,
		"cwd":           g.Cwd,
		"expiresAt":     time.UnixMilli(g.ExpiresAt).UTC().Format(time.RFC3339Nano),
	}
}

// Store keeps privilege grants in SQLite.
type Store struct {
	db *sql.DB
}

func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("grant store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS privilege_grants (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  command TEXT NOT NULL,
  cwd TEXT NOT NULL DEFAULT '.',
  command_sha256 TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS privilege_grants_owner_workspace ON privilege_grants(owner_id, workspace_id);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func newGrantID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("grants: crypto/rand unavailable")
	}
	return "pvg_" + hex.EncodeToString(buf)
}

func commandDigest(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

func (s *Store) Create(ownerID, workspaceID, command, cwd string, ttlMs int64) (Grant, error) {
	if cwd == "" {
		cwd = "."
	}
	if ttlMs <= 0 {
		ttlMs = 60_000
	}
	now := time.Now().UnixMilli()
	digest := commandDigest(command)
	var g Grant
	var consumed sql.NullInt64
	err := s.db.QueryRow(`SELECT id, owner_id, workspace_id, command, cwd, command_sha256, status, created_at, expires_at, consumed_at FROM privilege_grants WHERE owner_id = ? AND workspace_id = ? AND command_sha256 = ? AND cwd = ? AND status = 'PENDING' AND expires_at > ? ORDER BY created_at DESC LIMIT 1`,
		ownerID, workspaceID, digest, cwd, now).
		Scan(&g.ID, &g.OwnerID, &g.WorkspaceID, &g.Command, &g.Cwd, &g.CommandSHA256, &g.Status, &g.CreatedAt, &g.ExpiresAt, &consumed)
	if err == nil {
		g.ConsumedAt = consumed.Int64
		return g, nil
	}
	if err != sql.ErrNoRows {
		return Grant{}, err
	}
	g = Grant{
		ID: newGrantID(), OwnerID: ownerID, WorkspaceID: workspaceID, Command: command, Cwd: cwd,
		CommandSHA256: digest, Status: StatusPending, CreatedAt: now, ExpiresAt: now + ttlMs,
	}
	if _, err := s.db.Exec(`INSERT INTO privilege_grants (id, owner_id, workspace_id, command, cwd, command_sha256, status, created_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		g.ID, g.OwnerID, g.WorkspaceID, g.Command, g.Cwd, g.CommandSHA256, g.Status, g.CreatedAt, g.ExpiresAt); err != nil {
		return Grant{}, err
	}
	return g, nil
}

func (s *Store) Approve(ownerID, grantID string) bool {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`UPDATE privilege_grants SET status = 'APPROVED' WHERE id = ? AND owner_id = ? AND status = 'PENDING' AND expires_at > ?`, grantID, ownerID, now)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (s *Store) Consume(ownerID, workspaceID, grantID, commandSHA256, cwd string) bool {
	if cwd == "" {
		cwd = "."
	}
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`UPDATE privilege_grants SET status = 'CONSUMED', consumed_at = ? WHERE id = ? AND owner_id = ? AND workspace_id = ? AND command_sha256 = ? AND cwd = ? AND status = 'APPROVED' AND expires_at > ?`,
		now, grantID, ownerID, workspaceID, commandSHA256, cwd, now)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (s *Store) Reject(ownerID, grantID string) bool {
	res, err := s.db.Exec(`UPDATE privilege_grants SET status = 'REJECTED' WHERE id = ? AND owner_id = ? AND status = 'PENDING'`, grantID, ownerID)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (s *Store) List(ownerID, workspaceID string, limit int) []Grant {
	if limit < 1 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if workspaceID != "" {
		rows, err = s.db.Query(`SELECT id, owner_id, workspace_id, command, cwd, command_sha256, status, created_at, expires_at, consumed_at FROM privilege_grants WHERE owner_id = ? AND workspace_id = ? ORDER BY created_at DESC LIMIT ?`, ownerID, workspaceID, limit)
	} else {
		rows, err = s.db.Query(`SELECT id, owner_id, workspace_id, command, cwd, command_sha256, status, created_at, expires_at, consumed_at FROM privilege_grants WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?`, ownerID, limit)
	}
	if err != nil {
		return nil
	}
	defer rows.Close()
	now := time.Now().UnixMilli()
	out := []Grant{}
	for rows.Next() {
		var g Grant
		var consumed sql.NullInt64
		if err := rows.Scan(&g.ID, &g.OwnerID, &g.WorkspaceID, &g.Command, &g.Cwd, &g.CommandSHA256, &g.Status, &g.CreatedAt, &g.ExpiresAt, &consumed); err != nil {
			return out
		}
		g.ConsumedAt = consumed.Int64
		if (g.Status == StatusPending || g.Status == StatusApproved) && g.ExpiresAt <= now {
			g.Status = StatusExpired
		}
		out = append(out, g)
	}
	return out
}

func (s *Store) Get(grantID string) (Grant, bool) {
	var g Grant
	var consumed sql.NullInt64
	err := s.db.QueryRow(`SELECT id, owner_id, workspace_id, command, cwd, command_sha256, status, created_at, expires_at, consumed_at FROM privilege_grants WHERE id = ?`, grantID).
		Scan(&g.ID, &g.OwnerID, &g.WorkspaceID, &g.Command, &g.Cwd, &g.CommandSHA256, &g.Status, &g.CreatedAt, &g.ExpiresAt, &consumed)
	if err != nil {
		return Grant{}, false
	}
	g.ConsumedAt = consumed.Int64
	now := time.Now().UnixMilli()
	if (g.Status == StatusPending || g.Status == StatusApproved) && g.ExpiresAt <= now {
		_, _ = s.db.Exec(`UPDATE privilege_grants SET status = 'EXPIRED' WHERE id = ? AND status IN ('PENDING','APPROVED')`, grantID)
		g.Status = StatusExpired
	}
	return g, true
}

func SkillGrantCommand(name, script, expected string) string {
	return fmt.Sprintf("skills_run %s script=%s expected=%s", name, script, expected)
}

func SkillGrantDigest(name, script, expected string) string {
	return commandDigest(SkillGrantCommand(name, script, expected))
}

func ApprovalRequired(grant Grant, name, script string) protocol.ToolResult {
	got := protocol.Fail(protocol.ErrorPrivilegeApprovalRequired, fmt.Sprintf("Approval grant required to run skill script %s/%s in a disposable helper container", name, script), true)
	got.Error.GrantRequest = grant.RequestJSON()
	got.Message = "Skill execution requires explicit operator approval grant"
	return got
}
