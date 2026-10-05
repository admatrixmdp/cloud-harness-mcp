package hooks

import (
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

var sha256Hex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

var events = map[string]struct{}{
	"on_workspace_open": {},
	"post_checkout":     {},
	"pre_commit":        {},
	"post_commit":       {},
	"manual":            {},
}

const defaultRetentionMs = int64(30 * 86_400_000)

// Error is a public hook-activation failure.
type Error struct {
	Code    protocol.ErrorCode
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(code protocol.ErrorCode, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Activation is a retained lifecycle-hook grant.
type Activation struct {
	PrincipalID    string
	WorkspaceID    string
	Event          string
	ManifestSHA256 string
	CreatedAt      int64
	ExpiresAt      int64
}

func (a Activation) PublicJSON() map[string]any {
	return map[string]any{
		"principalId":    a.PrincipalID,
		"workspaceId":    a.WorkspaceID,
		"event":          a.Event,
		"manifestSha256": a.ManifestSHA256,
		"createdAt":      a.CreatedAt,
		"expiresAt":      a.ExpiresAt,
	}
}

// Store keeps hook activations in SQLite.
type Store struct {
	db *sql.DB
}

// Open creates the activations schema.
func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("hook store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS hook_activations (
  principal_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  event TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY(principal_id, workspace_id, event)
);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func validEvent(event string) bool {
	_, ok := events[event]
	return ok
}

func (s *Store) Activate(principalID, workspaceID, event, manifestSHA256 string, retentionSeconds int) (Activation, error) {
	if !validEvent(event) {
		return Activation{}, fail(protocol.ErrorInvalidInput, "invalid hook event")
	}
	if !sha256Hex.MatchString(manifestSHA256) {
		return Activation{}, fail(protocol.ErrorInvalidInput, "manifestSha256 must be a 64-character hex digest")
	}
	now := time.Now().UnixMilli()
	ttl := defaultRetentionMs
	if retentionSeconds > 0 {
		if retentionSeconds < 60 || retentionSeconds > 2_592_000 {
			return Activation{}, fail(protocol.ErrorInvalidInput, "retentionSeconds must be between 60 and 2592000")
		}
		ttl = int64(retentionSeconds) * 1000
	}
	expires := now + ttl
	if _, err := s.db.Exec(`INSERT INTO hook_activations (principal_id, workspace_id, event, manifest_sha256, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(principal_id, workspace_id, event) DO UPDATE SET manifest_sha256 = excluded.manifest_sha256, expires_at = excluded.expires_at`,
		principalID, workspaceID, event, manifestSHA256, now, expires); err != nil {
		return Activation{}, fail(protocol.ErrorInternal, err.Error())
	}
	return Activation{
		PrincipalID: principalID, WorkspaceID: workspaceID, Event: event,
		ManifestSHA256: manifestSHA256, CreatedAt: now, ExpiresAt: expires,
	}, nil
}

func (s *Store) Deactivate(principalID, workspaceID, event string) (bool, error) {
	if event != "" && !validEvent(event) {
		return false, fail(protocol.ErrorInvalidInput, "invalid hook event")
	}
	var res sql.Result
	var err error
	if event != "" {
		res, err = s.db.Exec(`DELETE FROM hook_activations WHERE principal_id = ? AND workspace_id = ? AND event = ?`, principalID, workspaceID, event)
	} else {
		res, err = s.db.Exec(`DELETE FROM hook_activations WHERE principal_id = ? AND workspace_id = ?`, principalID, workspaceID)
	}
	if err != nil {
		return false, fail(protocol.ErrorInternal, err.Error())
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) Active(principalID, workspaceID string) ([]Activation, error) {
	now := time.Now().UnixMilli()
	rows, err := s.db.Query(`SELECT principal_id, workspace_id, event, manifest_sha256, created_at, expires_at FROM hook_activations WHERE principal_id = ? AND workspace_id = ? AND expires_at > ? ORDER BY event`, principalID, workspaceID, now)
	if err != nil {
		return nil, fail(protocol.ErrorInternal, err.Error())
	}
	defer rows.Close()
	var out []Activation
	for rows.Next() {
		var a Activation
		if err := rows.Scan(&a.PrincipalID, &a.WorkspaceID, &a.Event, &a.ManifestSHA256, &a.CreatedAt, &a.ExpiresAt); err != nil {
			return nil, fail(protocol.ErrorInternal, err.Error())
		}
		out = append(out, a)
	}
	if out == nil {
		out = []Activation{}
	}
	return out, rows.Err()
}
