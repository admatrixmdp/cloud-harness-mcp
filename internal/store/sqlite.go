package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

// SQLite is the durable workspace metadata store (GoClaw style: database/sql, no ORM).
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens (or creates) a WAL workspace database.
func OpenSQLite(path string) (*SQLite, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  repository_url TEXT NOT NULL,
  repository_ref TEXT,
  container_name TEXT,
  status TEXT NOT NULL,
  network_profile TEXT NOT NULL CHECK(network_profile IN ('network-none','dependency-access')),
  fingerprint TEXT,
  generation INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  hard_expires_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS workspaces_owner_idempotency ON workspaces(owner_id, idempotency_key);
`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLite{db: db}, nil
}

// Close releases the database.
func (s *SQLite) Close() error { return s.db.Close() }

// Put inserts or replaces a workspace row.
func (s *SQLite) Put(rec Record) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO workspaces
		(id, owner_id, idempotency_key, repository_url, repository_ref, container_name, status, network_profile, fingerprint, generation, created_at, last_activity_at, expires_at, hard_expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.OwnerID, rec.IdempotencyKey, rec.RepositoryURL, nullString(rec.Ref), nullString(rec.ContainerName),
		string(rec.Status), string(rec.NetworkProfile), rec.Fingerprint, rec.Generation,
		rec.CreatedAt.UnixMilli(), rec.LastActivityAt.UnixMilli(), rec.ExpiresAt.UnixMilli(), rec.HardExpiresAt.UnixMilli(),
	)
	return err
}

// Get loads one workspace.
func (s *SQLite) Get(id string) (Record, bool) {
	return s.scanOne(`SELECT id, owner_id, idempotency_key, repository_url, repository_ref, container_name, status, network_profile, fingerprint, generation, created_at, last_activity_at, expires_at, hard_expires_at FROM workspaces WHERE id = ?`, id)
}

// ByIdempotency loads by owner+key.
func (s *SQLite) ByIdempotency(ownerID, key string) (Record, bool) {
	return s.scanOne(`SELECT id, owner_id, idempotency_key, repository_url, repository_ref, container_name, status, network_profile, fingerprint, generation, created_at, last_activity_at, expires_at, hard_expires_at FROM workspaces WHERE owner_id = ? AND idempotency_key = ?`, ownerID, key)
}

// List returns owner workspaces.
func (s *SQLite) List(ownerID string) []Record {
	rows, err := s.db.Query(`SELECT id, owner_id, idempotency_key, repository_url, repository_ref, container_name, status, network_profile, fingerprint, generation, created_at, last_activity_at, expires_at, hard_expires_at FROM workspaces WHERE owner_id = ? ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]Record, 0)
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// UpdateStatus mutates lifecycle status.
func (s *SQLite) UpdateStatus(id string, status Status) (Record, bool) {
	now := time.Now().UnixMilli()
	var err error
	if status == StatusClosed {
		_, err = s.db.Exec(`UPDATE workspaces SET status = ?, last_activity_at = ?, container_name = NULL WHERE id = ?`, string(status), now, id)
	} else {
		_, err = s.db.Exec(`UPDATE workspaces SET status = ?, last_activity_at = ? WHERE id = ?`, string(status), now, id)
	}
	if err != nil {
		return Record{}, false
	}
	return s.Get(id)
}

// RenewLease extends idle expiry without exceeding HardExpiresAt.
func (s *SQLite) RenewLease(id string, expiresAt, lastActivityAt time.Time) (Record, bool) {
	rec, ok := s.Get(id)
	if !ok {
		return Record{}, false
	}
	if rec.Status == StatusClosed || rec.Status == StatusFailed || rec.Status == StatusReaping {
		return rec, false
	}
	if expiresAt.After(rec.HardExpiresAt) {
		expiresAt = rec.HardExpiresAt
	}
	status := rec.Status
	if status == StatusExpiredRecoverable {
		status = StatusActive
	}
	if _, err := s.db.Exec(`UPDATE workspaces SET status = ?, expires_at = ?, last_activity_at = ? WHERE id = ?`,
		string(status), expiresAt.UnixMilli(), lastActivityAt.UnixMilli(), id); err != nil {
		return Record{}, false
	}
	return s.Get(id)
}

func (s *SQLite) scanOne(query string, args ...any) (Record, bool) {
	row := s.db.QueryRow(query, args...)
	rec, err := scanRecord(row)
	if err != nil {
		return Record{}, false
	}
	return rec, true
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRecord(row scanner) (Record, error) {
	var rec Record
	var ref, container sql.NullString
	var created, activity, expires, hard int64
	var status, profile string
	if err := row.Scan(&rec.ID, &rec.OwnerID, &rec.IdempotencyKey, &rec.RepositoryURL, &ref, &container, &status, &profile, &rec.Fingerprint, &rec.Generation, &created, &activity, &expires, &hard); err != nil {
		return Record{}, err
	}
	rec.Ref = ref.String
	rec.ContainerName = container.String
	rec.Status = Status(status)
	rec.NetworkProfile = protocol.NetworkProfile(profile)
	if !rec.NetworkProfile.Valid() {
		return Record{}, fmt.Errorf("invalid network_profile %q", profile)
	}
	rec.CreatedAt = time.UnixMilli(created)
	rec.LastActivityAt = time.UnixMilli(activity)
	rec.ExpiresAt = time.UnixMilli(expires)
	rec.HardExpiresAt = time.UnixMilli(hard)
	return rec, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
