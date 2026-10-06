package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

// Event is a retained dashboard audit row.
type Event struct {
	ID                string
	PrincipalID       string
	Action            string
	SubjectType       string
	SubjectID         string
	SubjectGeneration int
	Details           map[string]any
	CreatedAt         int64
	rowID             int64
}

// PublicJSON is the runner/dashboard projection. createdAt stays unix-ms like TS AuditView.
func (e Event) PublicJSON() map[string]any {
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	return map[string]any{
		"id":                e.ID,
		"action":            e.Action,
		"subjectType":       e.SubjectType,
		"subjectId":         e.SubjectID,
		"subjectGeneration": e.SubjectGeneration,
		"details":           details,
		"createdAt":         e.CreatedAt,
	}
}

// Store keeps principal-scoped audit events in SQLite.
type Store struct {
	db *sql.DB
}

func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("audit store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  subject_generation INTEGER NOT NULL,
  details_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_principal_created ON audit_events(principal_id, created_at DESC, id);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Record(principalID, action, subjectType, subjectID string, generation int, details map[string]any) (Event, error) {
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return Event{}, err
	}
	now := time.Now().UnixMilli()
	id := protocol.NewOpaqueID(protocol.PrefixAudit)
	if _, err := s.db.Exec(`INSERT INTO audit_events
		(id, principal_id, action, subject_type, subject_id, subject_generation, details_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, principalID, action, subjectType, subjectID, generation, string(raw), now); err != nil {
		return Event{}, err
	}
	return Event{
		ID: id, PrincipalID: principalID, Action: action, SubjectType: subjectType, SubjectID: subjectID,
		SubjectGeneration: generation, Details: details, CreatedAt: now,
	}, nil
}

func (s *Store) List(principalID, cursor string, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if cursor != "" {
		if !protocol.ValidOpaqueID(protocol.PrefixAudit, cursor) {
			return []Event{}, nil
		}
		var createdAt, sequence int64
		err := s.db.QueryRow(`SELECT created_at, rowid FROM audit_events WHERE principal_id = ? AND id = ?`, principalID, cursor).
			Scan(&createdAt, &sequence)
		if err == sql.ErrNoRows {
			return []Event{}, nil
		}
		if err != nil {
			return nil, err
		}
		rows, err := s.db.Query(`SELECT id, principal_id, action, subject_type, subject_id, subject_generation, details_json, created_at, rowid
			FROM audit_events WHERE principal_id = ?
			AND (created_at < ? OR (created_at = ? AND rowid < ?))
			ORDER BY created_at DESC, rowid DESC LIMIT ?`,
			principalID, createdAt, createdAt, sequence, limit)
		if err != nil {
			return nil, err
		}
		return scanEvents(rows)
	}
	rows, err := s.db.Query(`SELECT id, principal_id, action, subject_type, subject_id, subject_generation, details_json, created_at, rowid
		FROM audit_events WHERE principal_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?`, principalID, limit)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	defer rows.Close()
	out := make([]Event, 0)
	for rows.Next() {
		var e Event
		var raw string
		if err := rows.Scan(&e.ID, &e.PrincipalID, &e.Action, &e.SubjectType, &e.SubjectID, &e.SubjectGeneration, &raw, &e.CreatedAt, &e.rowID); err != nil {
			return nil, err
		}
		details := map[string]any{}
		if raw != "" {
			_ = json.Unmarshal([]byte(raw), &details)
		}
		e.Details = details
		out = append(out, e)
	}
	return out, rows.Err()
}
