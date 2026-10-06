package integrations

import (
	"database/sql"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

// EnvironmentID binds AES-GCM associated data so ciphertext cannot be
// decrypted as a model credential or workspace secret.
const EnvironmentID = "integration_credential"

var (
	ErrNotFound = fmt.Errorf("not found")
	ErrConflict = fmt.Errorf("conflict")
	ErrInvalid  = fmt.Errorf("invalid")
)

// Credential is dashboard-visible metadata. There is no value field.
type Credential struct {
	ID            string
	PrincipalID   string
	Integration   string
	Label         string
	Status        string
	ActiveVersion int
	Generation    int
	CreatedAt     int64
	UpdatedAt     int64
}

// PublicJSON never includes value or principalId.
func (c Credential) PublicJSON() map[string]any {
	return map[string]any{
		"id":            c.ID,
		"integration":   c.Integration,
		"label":         c.Label,
		"status":        c.Status,
		"activeVersion": c.ActiveVersion,
		"generation":    c.Generation,
		"createdAt":     c.CreatedAt,
		"updatedAt":     c.UpdatedAt,
	}
}

// Store encrypts TypeSafe (and later) integration keys with the runner keyring.
type Store struct {
	db      *sql.DB
	keyring *secrets.Keyring
}

// Open creates integration credential tables. Mutations require a keyring.
func Open(db *sql.DB, keyring *secrets.Keyring) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("integration credential store requires sqlite")
	}
	if keyring == nil {
		return nil, fmt.Errorf("integration credential operations are temporarily unavailable")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS integration_credentials (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  integration TEXT NOT NULL CHECK(integration IN ('typesafe')),
  label TEXT NOT NULL,
  active_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'DISABLED', 'REVOKED')),
  generation INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS integration_credentials_principal_idx
  ON integration_credentials(principal_id, integration);
CREATE TABLE IF NOT EXISTS integration_credential_versions (
  principal_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  key_version INTEGER NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  auth_tag BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(principal_id, credential_id, version)
);
`); err != nil {
		return nil, err
	}
	return &Store{db: db, keyring: keyring}, nil
}

func normalizeLabel(label string) (string, error) {
	value := strings.TrimSpace(label)
	if value == "" || utf8.RuneCountInString(value) > 120 {
		return "", fmt.Errorf("%w: label must contain 1 to 120 characters", ErrInvalid)
	}
	return value, nil
}

func normalizeIntegration(integration string) (string, error) {
	if integration != "typesafe" {
		return "", fmt.Errorf("%w: integration must be typesafe", ErrInvalid)
	}
	return integration, nil
}

func validateValue(value string) error {
	if value == "" || len(value) > 4096 {
		return fmt.Errorf("%w: a credential value is required", ErrInvalid)
	}
	return nil
}

func (s *Store) require(principalID, id string) (Credential, error) {
	var c Credential
	err := s.db.QueryRow(`SELECT id, principal_id, integration, label, status, active_version, generation, created_at, updated_at
		FROM integration_credentials WHERE principal_id = ? AND id = ?`, principalID, id).
		Scan(&c.ID, &c.PrincipalID, &c.Integration, &c.Label, &c.Status, &c.ActiveVersion, &c.Generation, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, err
	}
	return c, nil
}

// Create encrypts value immediately. The returned view never includes it.
func (s *Store) Create(principalID, integration, label, value string, now int64) (Credential, error) {
	integration, err := normalizeIntegration(integration)
	if err != nil {
		return Credential{}, err
	}
	label, err = normalizeLabel(label)
	if err != nil {
		return Credential{}, err
	}
	if err := validateValue(value); err != nil {
		return Credential{}, err
	}
	var existing string
	err = s.db.QueryRow(`SELECT id FROM integration_credentials WHERE principal_id = ? AND integration = ?`, principalID, integration).Scan(&existing)
	if err == nil {
		return Credential{}, fmt.Errorf("%w: a %s credential already exists; rotate it instead", ErrConflict, integration)
	}
	if err != nil && err != sql.ErrNoRows {
		return Credential{}, err
	}
	id := protocol.NewOpaqueID(protocol.PrefixIntegrationCredential)
	enc, err := s.keyring.EncryptString(value, secrets.Context{
		PrincipalID: principalID, EnvironmentID: EnvironmentID, Name: id, Version: 1,
	})
	if err != nil {
		return Credential{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Credential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO integration_credentials
		(id, principal_id, integration, label, active_version, status, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, 'ACTIVE', 1, ?, ?)`,
		id, principalID, integration, label, now, now); err != nil {
		return Credential{}, err
	}
	if _, err := tx.Exec(`INSERT INTO integration_credential_versions
		(principal_id, credential_id, version, key_version, nonce, ciphertext, auth_tag, created_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?)`,
		principalID, id, enc.KeyVersion, enc.Nonce, enc.Ciphertext, enc.AuthTag, now); err != nil {
		return Credential{}, err
	}
	if err := tx.Commit(); err != nil {
		return Credential{}, err
	}
	return s.require(principalID, id)
}

// List returns metadata only, never value.
func (s *Store) List(principalID string) ([]Credential, error) {
	rows, err := s.db.Query(`SELECT id, principal_id, integration, label, status, active_version, generation, created_at, updated_at
		FROM integration_credentials WHERE principal_id = ? ORDER BY created_at, id`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Credential, 0)
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.PrincipalID, &c.Integration, &c.Label, &c.Status, &c.ActiveVersion, &c.Generation, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Rotate encrypts a new version at the current generation.
func (s *Store) Rotate(principalID, id, value string, expectedGeneration int, now int64) (Credential, error) {
	if err := validateValue(value); err != nil {
		return Credential{}, err
	}
	current, err := s.require(principalID, id)
	if err != nil {
		return Credential{}, err
	}
	if current.Generation != expectedGeneration {
		return Credential{}, ErrConflict
	}
	next := current.ActiveVersion + 1
	enc, err := s.keyring.EncryptString(value, secrets.Context{
		PrincipalID: principalID, EnvironmentID: EnvironmentID, Name: current.ID, Version: next,
	})
	if err != nil {
		return Credential{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Credential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO integration_credential_versions
		(principal_id, credential_id, version, key_version, nonce, ciphertext, auth_tag, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		principalID, current.ID, next, enc.KeyVersion, enc.Nonce, enc.Ciphertext, enc.AuthTag, now); err != nil {
		return Credential{}, err
	}
	res, err := tx.Exec(`UPDATE integration_credentials SET active_version = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ?`,
		next, now, principalID, current.ID, expectedGeneration)
	if err != nil {
		return Credential{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return Credential{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Credential{}, err
	}
	return s.require(principalID, id)
}

// Delete removes the credential at the current generation.
func (s *Store) Delete(principalID, id string, expectedGeneration int) error {
	current, err := s.require(principalID, id)
	if err != nil {
		return err
	}
	if current.Generation != expectedGeneration {
		return ErrConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM integration_credential_versions WHERE principal_id = ? AND credential_id = ?`, principalID, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM integration_credentials WHERE principal_id = ? AND id = ?`, principalID, id); err != nil {
		return err
	}
	return tx.Commit()
}

// DecryptValue is the only path that opens ciphertext. Dashboard ops never call it.
func (s *Store) DecryptValue(principalID, integration string) (string, error) {
	var id string
	var version int
	err := s.db.QueryRow(`SELECT id, active_version FROM integration_credentials
		WHERE principal_id = ? AND integration = ? AND status = 'ACTIVE'`, principalID, integration).Scan(&id, &version)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var enc secrets.Encrypted
	err = s.db.QueryRow(`SELECT key_version, nonce, ciphertext, auth_tag FROM integration_credential_versions
		WHERE principal_id = ? AND credential_id = ? AND version = ?`, principalID, id, version).
		Scan(&enc.KeyVersion, &enc.Nonce, &enc.Ciphertext, &enc.AuthTag)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return s.keyring.DecryptString(enc, secrets.Context{
		PrincipalID: principalID, EnvironmentID: EnvironmentID, Name: id, Version: version,
	})
}
