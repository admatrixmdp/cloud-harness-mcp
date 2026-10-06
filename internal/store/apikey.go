package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	maxActiveAPIKeys = 10
	usageInterval    = 5 * time.Minute
)

// APIKeyRecord is the dashboard-visible metadata. Secret is never stored here.
type APIKeyRecord struct {
	ID            string
	PrincipalID   string
	Name          string
	DisplayPrefix string
	State         protocol.APIKeyState
	Generation    int
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastUsedAt    *time.Time
	RevokedAt     *time.Time
}

// EnsureAPIKeys creates the api_keys table if missing.
func (s *SQLite) EnsureAPIKeys() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  name TEXT NOT NULL,
  display_prefix TEXT NOT NULL,
  secret_hash BLOB NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ACTIVE','REVOKED')),
  generation INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS api_keys_principal ON api_keys(principal_id, created_at);
`)
	return err
}

// CreateAPIKey inserts a hashed key. The plaintext is returned once and never stored.
func (s *SQLite) CreateAPIKey(principalID, name string, expiresInDays int, now time.Time) (APIKeyRecord, string, error) {
	if err := s.EnsureAPIKeys(); err != nil {
		return APIKeyRecord{}, "", err
	}
	name = trimName(name)
	if name == "" || expiresInDays < 1 || expiresInDays > protocol.APIKeyMaxExpiryDays {
		return APIKeyRecord{}, "", fmt.Errorf("invalid API key request")
	}
	var active int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE principal_id = ? AND state = 'ACTIVE' AND expires_at > ?`, principalID, now.UnixMilli()).Scan(&active); err != nil {
		return APIKeyRecord{}, "", err
	}
	if active >= maxActiveAPIKeys {
		return APIKeyRecord{}, "", fmt.Errorf("active API key limit reached")
	}
	idBytes := make([]byte, 18)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return APIKeyRecord{}, "", err
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return APIKeyRecord{}, "", err
	}
	id := "apk_" + base64.RawURLEncoding.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	if !protocol.ValidAPIKeyID(id) {
		return APIKeyRecord{}, "", fmt.Errorf("unable to allocate API key identity")
	}
	plaintext := "chm_key_" + id + "." + secret
	rec := APIKeyRecord{
		ID:            id,
		PrincipalID:   principalID,
		Name:          name,
		DisplayPrefix: auth.DisplayPrefix(id),
		State:         protocol.APIKeyActive,
		Generation:    1,
		CreatedAt:     now,
		ExpiresAt:     now.Add(time.Duration(expiresInDays) * 24 * time.Hour),
	}
	if _, err := s.db.Exec(`INSERT INTO api_keys (id, principal_id, name, display_prefix, secret_hash, state, generation, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, 'ACTIVE', 1, ?, ?)`,
		rec.ID, rec.PrincipalID, rec.Name, rec.DisplayPrefix, auth.HashSecret(secret), rec.CreatedAt.UnixMilli(), rec.ExpiresAt.UnixMilli()); err != nil {
		return APIKeyRecord{}, "", err
	}
	auth.LogKeyEvent("created", rec.ID)
	return rec, plaintext, nil
}

// ListAPIKeys returns dashboard metadata for one principal. Secret hashes never leave the store.
func (s *SQLite) ListAPIKeys(principalID string, now time.Time) ([]APIKeyRecord, error) {
	if err := s.EnsureAPIKeys(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT id, principal_id, name, display_prefix, state, generation, created_at, expires_at, last_used_at, revoked_at
		FROM api_keys WHERE principal_id = ? ORDER BY created_at DESC, id`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]APIKeyRecord, 0)
	for rows.Next() {
		rec, err := scanAPIKey(rows, now)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// GetAPIKey loads one key owned by principalID.
func (s *SQLite) GetAPIKey(principalID, keyID string, now time.Time) (APIKeyRecord, bool) {
	if err := s.EnsureAPIKeys(); err != nil {
		return APIKeyRecord{}, false
	}
	row := s.db.QueryRow(`SELECT id, principal_id, name, display_prefix, state, generation, created_at, expires_at, last_used_at, revoked_at
		FROM api_keys WHERE principal_id = ? AND id = ?`, principalID, keyID)
	rec, err := scanAPIKey(row, now)
	if err != nil {
		return APIKeyRecord{}, false
	}
	return rec, true
}

// GetAPIKeyByID loads a key by id for authentication. It never returns the secret hash.
func (s *SQLite) GetAPIKeyByID(keyID string, now time.Time) (APIKeyRecord, bool) {
	if err := s.EnsureAPIKeys(); err != nil {
		return APIKeyRecord{}, false
	}
	row := s.db.QueryRow(`SELECT id, principal_id, name, display_prefix, state, generation, created_at, expires_at, last_used_at, revoked_at
		FROM api_keys WHERE id = ?`, keyID)
	rec, err := scanAPIKey(row, now)
	if err != nil {
		return APIKeyRecord{}, false
	}
	return rec, true
}

// VerifyAPIKey constant-time compares the secret hash. It never logs the raw key.
func (s *SQLite) VerifyAPIKey(apiKey string, now time.Time) (keyID string, ok bool) {
	if err := s.EnsureAPIKeys(); err != nil {
		return "", false
	}
	id, secret, ok := auth.ParseAPIKey(apiKey)
	if !ok {
		return "", false
	}
	var hash []byte
	var state string
	var expiresAt int64
	err := s.db.QueryRow(`SELECT secret_hash, state, expires_at FROM api_keys WHERE id = ?`, id).Scan(&hash, &state, &expiresAt)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil || state != "ACTIVE" || expiresAt <= now.UnixMilli() {
		return "", false
	}
	if !auth.VerifySecret(secret, hash) {
		return "", false
	}
	_, _ = s.db.Exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at <= ?)`,
		now.UnixMilli(), id, now.Add(-usageInterval).UnixMilli())
	return id, true
}

// RevokeAPIKey marks a key unusable.
func (s *SQLite) RevokeAPIKey(principalID, keyID string, expectedGeneration int, now time.Time) (APIKeyRecord, bool) {
	if err := s.EnsureAPIKeys(); err != nil {
		return APIKeyRecord{}, false
	}
	res, err := s.db.Exec(`UPDATE api_keys SET state = 'REVOKED', generation = generation + 1, revoked_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		now.UnixMilli(), principalID, keyID, expectedGeneration)
	if err != nil {
		return APIKeyRecord{}, false
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return APIKeyRecord{}, false
	}
	auth.LogKeyEvent("revoked", keyID)
	rec, ok := s.GetAPIKey(principalID, keyID, now)
	if !ok {
		return APIKeyRecord{}, false
	}
	return rec, true
}

type apiKeyScanner interface {
	Scan(dest ...any) error
}

func scanAPIKey(row apiKeyScanner, now time.Time) (APIKeyRecord, error) {
	var rec APIKeyRecord
	var created, expires int64
	var lastUsed, revoked sql.NullInt64
	var state string
	if err := row.Scan(&rec.ID, &rec.PrincipalID, &rec.Name, &rec.DisplayPrefix, &state, &rec.Generation, &created, &expires, &lastUsed, &revoked); err != nil {
		return APIKeyRecord{}, err
	}
	rec.CreatedAt = time.UnixMilli(created)
	rec.ExpiresAt = time.UnixMilli(expires)
	if lastUsed.Valid {
		t := time.UnixMilli(lastUsed.Int64)
		rec.LastUsedAt = &t
	}
	if revoked.Valid {
		t := time.UnixMilli(revoked.Int64)
		rec.RevokedAt = &t
	}
	if state == "REVOKED" {
		rec.State = protocol.APIKeyRevoked
	} else if expires <= now.UnixMilli() {
		rec.State = protocol.APIKeyExpired
	} else {
		rec.State = protocol.APIKeyActive
	}
	return rec, nil
}

// PublicJSON is the dashboard-visible metadata. Secret hashes never appear.
func (r APIKeyRecord) PublicJSON() map[string]any {
	out := map[string]any{
		"id":            r.ID,
		"name":          r.Name,
		"displayPrefix": r.DisplayPrefix,
		"state":         string(r.State),
		"generation":    r.Generation,
		"createdAt":     r.CreatedAt.UnixMilli(),
		"expiresAt":     r.ExpiresAt.UnixMilli(),
		"lastUsedAt":    nil,
		"revokedAt":     nil,
	}
	if r.LastUsedAt != nil {
		out["lastUsedAt"] = r.LastUsedAt.UnixMilli()
	}
	if r.RevokedAt != nil {
		out["revokedAt"] = r.RevokedAt.UnixMilli()
	}
	return out
}

func trimName(name string) string {
	out := name
	for len(out) > 0 && (out[0] == ' ' || out[0] == '\t') {
		out = out[1:]
	}
	for len(out) > 0 && (out[len(out)-1] == ' ' || out[len(out)-1] == '\t') {
		out = out[:len(out)-1]
	}
	if len(out) > 100 {
		return ""
	}
	return out
}
