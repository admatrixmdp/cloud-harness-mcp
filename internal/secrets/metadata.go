package secrets

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

// View is dashboard-visible secret metadata. Plaintext is never included.
type View struct {
	ID            string
	EnvironmentID string
	Name          string
	Description   string
	Purpose       string
	State         string
	Version       int
	Generation    int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Store persists AES-GCM envelopes. Ciphertext stays on the runner.
type Store struct {
	db      *sql.DB
	keyring *Keyring
}

// OpenMetadata creates the secret tables if missing and asserts stored key versions.
func OpenMetadata(db *sql.DB, keyring *Keyring) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("secret store requires sqlite")
	}
	if keyring == nil {
		return nil, fmt.Errorf("secret keyring is unavailable")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS secret_references (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  purpose TEXT NOT NULL DEFAULT 'runtime',
  state TEXT NOT NULL CHECK(state IN ('ACTIVE','DELETED')),
  current_version INTEGER NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS secret_references_owner_env_name
  ON secret_references(principal_id, environment_id, name);
CREATE TABLE IF NOT EXISTS secret_versions (
  principal_id TEXT NOT NULL,
  secret_reference_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  key_version INTEGER NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  auth_tag BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (principal_id, secret_reference_id, version)
);
`); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT DISTINCT key_version FROM secret_versions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	if err := keyring.AssertAvailableVersions(versions); err != nil {
		return nil, err
	}
	return &Store{db: db, keyring: keyring}, nil
}

// Create encrypts value bound to principal/environment/name/version. It never
// stores or returns plaintext.
func (s *Store) Create(principalID, environmentID, name, value, description string, now time.Time) (View, error) {
	if err := protocol.ValidateSecretName(name); err != nil {
		return View{}, err
	}
	if err := protocol.ValidateSecretValue(value); err != nil {
		return View{}, err
	}
	enc, err := s.keyring.EncryptString(value, Context{
		PrincipalID: principalID, EnvironmentID: environmentID, Name: name, Version: 1,
	})
	if err != nil {
		return View{}, err
	}
	id := protocol.NewOpaqueID(protocol.PrefixSecret)
	if _, err := s.db.Exec(`INSERT INTO secret_references
		(id, principal_id, environment_id, name, description, purpose, state, current_version, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'runtime', 'ACTIVE', 1, 1, ?, ?)`,
		id, principalID, environmentID, name, description, now.UnixMilli(), now.UnixMilli()); err != nil {
		return View{}, err
	}
	if _, err := s.db.Exec(`INSERT INTO secret_versions
		(principal_id, secret_reference_id, version, key_version, nonce, ciphertext, auth_tag, created_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?)`,
		principalID, id, enc.KeyVersion, enc.Nonce, enc.Ciphertext, enc.AuthTag, now.UnixMilli()); err != nil {
		return View{}, err
	}
	return View{
		ID: id, EnvironmentID: environmentID, Name: name, Description: description,
		Purpose: "runtime", State: "ACTIVE", Version: 1, Generation: 1,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

// Decrypt returns plaintext for injection. Callers must not log the value.
func (s *Store) Decrypt(principalID, environmentID, name string) (string, error) {
	var id string
	var version int
	err := s.db.QueryRow(`SELECT id, current_version FROM secret_references
		WHERE principal_id = ? AND environment_id = ? AND name = ? AND state = 'ACTIVE'`,
		principalID, environmentID, name).Scan(&id, &version)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("secret not found")
	}
	if err != nil {
		return "", err
	}
	var enc Encrypted
	if err := s.db.QueryRow(`SELECT key_version, nonce, ciphertext, auth_tag FROM secret_versions
		WHERE principal_id = ? AND secret_reference_id = ? AND version = ?`,
		principalID, id, version).Scan(&enc.KeyVersion, &enc.Nonce, &enc.Ciphertext, &enc.AuthTag); err != nil {
		return "", err
	}
	return s.keyring.DecryptString(enc, Context{
		PrincipalID: principalID, EnvironmentID: environmentID, Name: name, Version: version,
	})
}

// List returns metadata only.
func (s *Store) List(principalID, environmentID string) ([]View, error) {
	rows, err := s.db.Query(`SELECT id, environment_id, name, IFNULL(description,''), purpose, state, current_version, generation, created_at, updated_at
		FROM secret_references WHERE principal_id = ? AND environment_id = ? AND state = 'ACTIVE' ORDER BY name`,
		principalID, environmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []View
	for rows.Next() {
		var v View
		var created, updated int64
		if err := rows.Scan(&v.ID, &v.EnvironmentID, &v.Name, &v.Description, &v.Purpose, &v.State, &v.Version, &v.Generation, &created, &updated); err != nil {
			return nil, err
		}
		v.CreatedAt = time.UnixMilli(created)
		v.UpdatedAt = time.UnixMilli(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}
