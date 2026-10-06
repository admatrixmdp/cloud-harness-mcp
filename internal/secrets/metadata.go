package secrets

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/audit"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

const globalEnvironmentID = "global"

// ErrConflict is a generation or uniqueness miss, mapped to CONFLICT.
var ErrConflict = fmt.Errorf("conflict")

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
	DeletedAt     *int64
}

// PublicJSON is the runner/dashboard projection. Never includes value.
func (v View) PublicJSON() map[string]any {
	var deleted any
	if v.DeletedAt != nil {
		deleted = *v.DeletedAt
	}
	var description any
	if v.Description != "" {
		description = v.Description
	}
	return map[string]any{
		"id":            v.ID,
		"environmentId": v.EnvironmentID,
		"name":          v.Name,
		"description":   description,
		"purpose":       v.Purpose,
		"state":         v.State,
		"version":       v.Version,
		"generation":    v.Generation,
		"createdAt":     v.CreatedAt.UnixMilli(),
		"updatedAt":     v.UpdatedAt.UnixMilli(),
		"deletedAt":     deleted,
	}
}

// EnvironmentHost reports whether an environment is ACTIVE under an ACTIVE project.
type EnvironmentHost interface {
	HasActiveEnvironment(principalID, environmentID string) bool
}

// Store persists AES-GCM envelopes. Ciphertext stays on the runner.
type Store struct {
	db      *sql.DB
	keyring *Keyring
	envs    EnvironmentHost
	audit   *audit.Store
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
CREATE TABLE IF NOT EXISTS global_secret_references (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
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
CREATE UNIQUE INDEX IF NOT EXISTS global_secret_references_owner_name
  ON global_secret_references(principal_id, name);
CREATE TABLE IF NOT EXISTS global_secret_versions (
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
	versions, err := distinctKeyVersions(db, `SELECT DISTINCT key_version FROM secret_versions UNION SELECT DISTINCT key_version FROM global_secret_versions`)
	if err != nil {
		return nil, err
	}
	if err := keyring.AssertAvailableVersions(versions); err != nil {
		return nil, err
	}
	return &Store{db: db, keyring: keyring}, nil
}

func distinctKeyVersions(db *sql.DB, query string) ([]int, error) {
	rows, err := db.Query(query)
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
	return versions, rows.Err()
}

// WithEnvironments binds ACTIVE environment checks for dashboard mutations.
func (s *Store) WithEnvironments(host EnvironmentHost) *Store {
	s.envs = host
	return s
}

// WithAudit records secret mutations on the shared audit log.
func (s *Store) WithAudit(store *audit.Store) *Store {
	s.audit = store
	return s
}

func (s *Store) record(principalID, action, subjectType, subjectID string, generation int, details map[string]any) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Record(principalID, action, subjectType, subjectID, generation, details)
}

func normalizePurpose(purpose string) (string, error) {
	if purpose == "" {
		return "runtime", nil
	}
	if purpose != "runtime" && purpose != "provisioning" {
		return "", fmt.Errorf("secret purpose must be runtime or provisioning")
	}
	return purpose, nil
}

func optionalDescription(raw *string) (string, error) {
	if raw == nil {
		return "", nil
	}
	return protocol.ValidateSecretDescription(*raw)
}

func insertVersion(tx *sql.Tx, table, principalID, secretID string, version int, enc Encrypted, now int64) error {
	_, err := tx.Exec(`INSERT INTO `+table+`
		(principal_id, secret_reference_id, version, key_version, nonce, ciphertext, auth_tag, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		principalID, secretID, version, enc.KeyVersion, enc.Nonce, enc.Ciphertext, enc.AuthTag, now)
	return err
}

func scanView(row interface{ Scan(dest ...any) error }, environmentID string) (View, error) {
	var v View
	var created, updated int64
	var deleted sql.NullInt64
	var description sql.NullString
	if err := row.Scan(&v.ID, &v.Name, &description, &v.Purpose, &v.State, &v.Version, &v.Generation, &created, &updated, &deleted); err != nil {
		return View{}, err
	}
	v.EnvironmentID = environmentID
	if description.Valid {
		v.Description = description.String
	}
	v.CreatedAt = time.UnixMilli(created)
	v.UpdatedAt = time.UnixMilli(updated)
	if deleted.Valid {
		n := deleted.Int64
		v.DeletedAt = &n
	}
	return v, nil
}

func (s *Store) hasActiveEnvironment(principalID, environmentID string) bool {
	if s.envs == nil {
		return true
	}
	return s.envs.HasActiveEnvironment(principalID, environmentID)
}

// Create encrypts value bound to principal/environment/name/version. It never
// stores or returns plaintext.
func (s *Store) Create(principalID, environmentID, name, value, description string, now time.Time) (View, error) {
	return s.CreateScoped(principalID, environmentID, name, value, 0, description, "runtime", now)
}

// CreateScoped is the dashboard create path. expectedGeneration must be 0.
func (s *Store) CreateScoped(principalID, environmentID, name, value string, expectedGeneration int, description, purpose string, now time.Time) (View, error) {
	if expectedGeneration != 0 {
		return View{}, ErrConflict
	}
	if err := protocol.ValidateSecretName(name); err != nil {
		return View{}, err
	}
	if err := protocol.ValidateSecretValue(value); err != nil {
		return View{}, err
	}
	desc, err := protocol.ValidateSecretDescription(description)
	if err != nil {
		return View{}, err
	}
	purpose, err = normalizePurpose(purpose)
	if err != nil {
		return View{}, err
	}
	if !s.hasActiveEnvironment(principalID, environmentID) {
		return View{}, ErrConflict
	}
	enc, err := s.keyring.EncryptString(value, Context{
		PrincipalID: principalID, EnvironmentID: environmentID, Name: name, Version: 1,
	})
	if err != nil {
		return View{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM secret_references WHERE principal_id = ? AND environment_id = ? AND name = ?`,
		principalID, environmentID, name).Scan(&exists); err != sql.ErrNoRows {
		if err == nil {
			return View{}, ErrConflict
		}
		return View{}, err
	}
	id := protocol.NewOpaqueID(protocol.PrefixSecret)
	ms := now.UnixMilli()
	if _, err := tx.Exec(`INSERT INTO secret_references
		(id, principal_id, environment_id, name, description, purpose, state, current_version, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 1, 1, ?, ?)`,
		id, principalID, environmentID, name, nullIfEmpty(desc), purpose, ms, ms); err != nil {
		return View{}, err
	}
	if err := insertVersion(tx, "secret_versions", principalID, id, 1, enc, ms); err != nil {
		return View{}, err
	}
	if err := tx.Commit(); err != nil {
		return View{}, err
	}
	s.record(principalID, "secret.created", "secret", id, 1, map[string]any{"environmentId": environmentID, "version": 1})
	return View{
		ID: id, EnvironmentID: environmentID, Name: name, Description: desc,
		Purpose: purpose, State: "ACTIVE", Version: 1, Generation: 1,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
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
	rows, err := s.db.Query(`SELECT id, name, description, purpose, state, current_version, generation, created_at, updated_at, deleted_at
		FROM secret_references WHERE principal_id = ? AND environment_id = ? AND state = 'ACTIVE' ORDER BY name`,
		principalID, environmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]View, 0)
	for rows.Next() {
		v, err := scanView(rows, environmentID)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListDashboard returns ACTIVE secret metadata joined to ACTIVE env/project.
func (s *Store) ListDashboard(principalID, environmentID string) ([]View, error) {
	rows, err := s.db.Query(`SELECT refs.id, refs.name, refs.description, refs.purpose, refs.state, refs.current_version, refs.generation, refs.created_at, refs.updated_at, refs.deleted_at
		FROM secret_references refs
		JOIN environments env ON env.principal_id = refs.principal_id AND env.id = refs.environment_id
		JOIN projects ON projects.principal_id = env.principal_id AND projects.id = env.project_id
		WHERE refs.principal_id = ? AND refs.environment_id = ? AND refs.state = 'ACTIVE'
			AND env.state = 'ACTIVE' AND projects.state = 'ACTIVE'
		ORDER BY refs.updated_at DESC, refs.id`, principalID, environmentID)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return []View{}, nil
		}
		return nil, err
	}
	defer rows.Close()
	out := make([]View, 0)
	for rows.Next() {
		v, err := scanView(rows, environmentID)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) byName(tx queryer, principalID, environmentID, name string) (View, error) {
	row := tx.QueryRow(`SELECT id, name, description, purpose, state, current_version, generation, created_at, updated_at, deleted_at
		FROM secret_references WHERE principal_id = ? AND environment_id = ? AND name = ?`, principalID, environmentID, name)
	v, err := scanView(row, environmentID)
	if err == sql.ErrNoRows {
		return View{}, ErrConflict
	}
	return v, err
}

type queryer interface {
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

// Rotate encrypts a new version. Plaintext is never stored.
func (s *Store) Rotate(principalID, environmentID, name, value string, expectedGeneration int, description *string, now time.Time) (View, error) {
	if err := protocol.ValidateSecretName(name); err != nil {
		return View{}, err
	}
	if err := protocol.ValidateSecretValue(value); err != nil {
		return View{}, err
	}
	desc, err := optionalDescription(description)
	if err != nil {
		return View{}, err
	}
	if !s.hasActiveEnvironment(principalID, environmentID) {
		return View{}, ErrConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.byName(tx, principalID, environmentID, name)
	if err != nil {
		return View{}, err
	}
	if current.State != "ACTIVE" || current.Generation != expectedGeneration {
		return View{}, ErrConflict
	}
	version := current.Version + 1
	enc, err := s.keyring.EncryptString(value, Context{
		PrincipalID: principalID, EnvironmentID: environmentID, Name: name, Version: version,
	})
	if err != nil {
		return View{}, err
	}
	ms := now.UnixMilli()
	if err := insertVersion(tx, "secret_versions", principalID, current.ID, version, enc, ms); err != nil {
		return View{}, err
	}
	finalDesc := current.Description
	if description != nil {
		finalDesc = desc
	}
	res, err := tx.Exec(`UPDATE secret_references
		SET current_version = ?, description = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		version, nullIfEmpty(finalDesc), ms, principalID, current.ID, current.Generation)
	if err != nil {
		return View{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return View{}, fmt.Errorf("secret generation changed during rotation")
	}
	if err := tx.Commit(); err != nil {
		return View{}, err
	}
	updated, err := s.byName(s.db, principalID, environmentID, name)
	if err != nil {
		return View{}, err
	}
	s.record(principalID, "secret.rotated", "secret", current.ID, updated.Generation, map[string]any{"environmentId": environmentID, "version": version})
	return updated, nil
}

// UpdateMetadata changes description only.
func (s *Store) UpdateMetadata(principalID, environmentID, name string, description *string, expectedGeneration int, now time.Time) (View, error) {
	if err := protocol.ValidateSecretName(name); err != nil {
		return View{}, err
	}
	desc, err := optionalDescription(description)
	if err != nil {
		return View{}, err
	}
	if !s.hasActiveEnvironment(principalID, environmentID) {
		return View{}, ErrConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.byName(tx, principalID, environmentID, name)
	if err != nil {
		return View{}, err
	}
	if current.State != "ACTIVE" || current.Generation != expectedGeneration {
		return View{}, ErrConflict
	}
	ms := now.UnixMilli()
	res, err := tx.Exec(`UPDATE secret_references
		SET description = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		nullIfEmpty(desc), ms, principalID, current.ID, expectedGeneration)
	if err != nil {
		return View{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return View{}, fmt.Errorf("secret generation changed during metadata update")
	}
	if err := tx.Commit(); err != nil {
		return View{}, err
	}
	updated, err := s.byName(s.db, principalID, environmentID, name)
	if err != nil {
		return View{}, err
	}
	s.record(principalID, "secret.updated", "secret", current.ID, updated.Generation, map[string]any{"environmentId": environmentID, "version": current.Version})
	return updated, nil
}

// Delete physically removes ciphertext. Delete-only name shape allows reserved names.
func (s *Store) Delete(principalID, environmentID, name string, expectedGeneration int, now time.Time) (View, error) {
	if err := protocol.ValidateSecretNameShape(name); err != nil {
		return View{}, err
	}
	if !s.hasActiveEnvironment(principalID, environmentID) {
		return View{}, ErrConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.byName(tx, principalID, environmentID, name)
	if err != nil {
		return View{}, err
	}
	if current.State != "ACTIVE" || current.Generation != expectedGeneration {
		return View{}, ErrConflict
	}
	if _, err := tx.Exec(`DELETE FROM secret_versions WHERE principal_id = ? AND secret_reference_id = ?`, principalID, current.ID); err != nil {
		return View{}, err
	}
	res, err := tx.Exec(`DELETE FROM secret_references WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		principalID, current.ID, expectedGeneration)
	if err != nil {
		return View{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return View{}, fmt.Errorf("secret generation changed during deletion")
	}
	if err := tx.Commit(); err != nil {
		return View{}, err
	}
	ms := now.UnixMilli()
	updated := current
	updated.State = "DELETED"
	updated.Generation = current.Generation + 1
	updated.UpdatedAt = now
	updated.DeletedAt = &ms
	s.record(principalID, "secret.deleted", "secret", current.ID, updated.Generation, map[string]any{"environmentId": environmentID, "version": updated.Version})
	return updated, nil
}

// BulkItem is one create/rotate step. Values are never logged.
type BulkItem struct {
	Name               string  `json:"name"`
	Value              string  `json:"value"`
	Description        *string `json:"description"`
	Purpose            string  `json:"purpose"`
	Action             string  `json:"action"`
	ExpectedGeneration int     `json:"expectedGeneration"`
}

// BulkApply creates or rotates 1–200 secrets in one transaction.
func (s *Store) BulkApply(principalID, environmentID string, items []BulkItem, now time.Time) ([]View, error) {
	if len(items) < 1 || len(items) > 200 {
		return nil, fmt.Errorf("bulk items must contain 1 to 200 entries")
	}
	if !s.hasActiveEnvironment(principalID, environmentID) {
		return nil, ErrConflict
	}
	out := make([]View, 0, len(items))
	for _, item := range items {
		var view View
		var err error
		switch item.Action {
		case "create":
			desc := ""
			if item.Description != nil {
				desc = *item.Description
			}
			view, err = s.CreateScoped(principalID, environmentID, item.Name, item.Value, 0, desc, item.Purpose, now)
		case "rotate":
			view, err = s.Rotate(principalID, environmentID, item.Name, item.Value, item.ExpectedGeneration, item.Description, now)
		default:
			return nil, fmt.Errorf("bulk action must be create or rotate")
		}
		if err != nil {
			return nil, err
		}
		out = append(out, view)
	}
	return out, nil
}

func (s *Store) globalByName(tx queryer, principalID, name string) (View, error) {
	row := tx.QueryRow(`SELECT id, name, description, purpose, state, current_version, generation, created_at, updated_at, deleted_at
		FROM global_secret_references WHERE principal_id = ? AND name = ?`, principalID, name)
	v, err := scanView(row, globalEnvironmentID)
	if err == sql.ErrNoRows {
		return View{}, ErrConflict
	}
	return v, err
}

// ListGlobal returns ACTIVE global secret metadata. environmentId is always "global".
func (s *Store) ListGlobal(principalID string) ([]View, error) {
	rows, err := s.db.Query(`SELECT id, name, description, purpose, state, current_version, generation, created_at, updated_at, deleted_at
		FROM global_secret_references WHERE principal_id = ? AND state = 'ACTIVE' ORDER BY updated_at DESC, id`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]View, 0)
	for rows.Next() {
		v, err := scanView(rows, globalEnvironmentID)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// CreateGlobal encrypts a principal-scoped secret with environmentId "global".
func (s *Store) CreateGlobal(principalID, name, value string, expectedGeneration int, description, purpose string, now time.Time) (View, error) {
	if expectedGeneration != 0 {
		return View{}, ErrConflict
	}
	if err := protocol.ValidateSecretName(name); err != nil {
		return View{}, err
	}
	if err := protocol.ValidateSecretValue(value); err != nil {
		return View{}, err
	}
	desc, err := protocol.ValidateSecretDescription(description)
	if err != nil {
		return View{}, err
	}
	purpose, err = normalizePurpose(purpose)
	if err != nil {
		return View{}, err
	}
	enc, err := s.keyring.EncryptString(value, Context{
		PrincipalID: principalID, EnvironmentID: globalEnvironmentID, Name: name, Version: 1,
	})
	if err != nil {
		return View{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM global_secret_references WHERE principal_id = ? AND name = ?`, principalID, name).Scan(&exists); err != sql.ErrNoRows {
		if err == nil {
			return View{}, ErrConflict
		}
		return View{}, err
	}
	id := protocol.NewOpaqueID(protocol.PrefixGlobalSecret)
	ms := now.UnixMilli()
	if _, err := tx.Exec(`INSERT INTO global_secret_references
		(id, principal_id, name, description, purpose, state, current_version, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'ACTIVE', 1, 1, ?, ?)`,
		id, principalID, name, nullIfEmpty(desc), purpose, ms, ms); err != nil {
		return View{}, err
	}
	if err := insertVersion(tx, "global_secret_versions", principalID, id, 1, enc, ms); err != nil {
		return View{}, err
	}
	if err := tx.Commit(); err != nil {
		return View{}, err
	}
	s.record(principalID, "global_secret.created", "global_secret", id, 1, map[string]any{"version": 1})
	return View{
		ID: id, EnvironmentID: globalEnvironmentID, Name: name, Description: desc,
		Purpose: purpose, State: "ACTIVE", Version: 1, Generation: 1,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

// RotateGlobal encrypts a new global version.
func (s *Store) RotateGlobal(principalID, name, value string, expectedGeneration int, description *string, now time.Time) (View, error) {
	if err := protocol.ValidateSecretName(name); err != nil {
		return View{}, err
	}
	if err := protocol.ValidateSecretValue(value); err != nil {
		return View{}, err
	}
	desc, err := optionalDescription(description)
	if err != nil {
		return View{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.globalByName(tx, principalID, name)
	if err != nil {
		return View{}, err
	}
	if current.State != "ACTIVE" || current.Generation != expectedGeneration {
		return View{}, ErrConflict
	}
	version := current.Version + 1
	enc, err := s.keyring.EncryptString(value, Context{
		PrincipalID: principalID, EnvironmentID: globalEnvironmentID, Name: name, Version: version,
	})
	if err != nil {
		return View{}, err
	}
	ms := now.UnixMilli()
	if err := insertVersion(tx, "global_secret_versions", principalID, current.ID, version, enc, ms); err != nil {
		return View{}, err
	}
	finalDesc := current.Description
	if description != nil {
		finalDesc = desc
	}
	res, err := tx.Exec(`UPDATE global_secret_references
		SET current_version = ?, description = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		version, nullIfEmpty(finalDesc), ms, principalID, current.ID, current.Generation)
	if err != nil {
		return View{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return View{}, fmt.Errorf("global secret generation changed during rotation")
	}
	if err := tx.Commit(); err != nil {
		return View{}, err
	}
	updated, err := s.globalByName(s.db, principalID, name)
	if err != nil {
		return View{}, err
	}
	s.record(principalID, "global_secret.rotated", "global_secret", current.ID, updated.Generation, map[string]any{"version": version})
	return updated, nil
}

// UpdateGlobalMetadata changes description only.
func (s *Store) UpdateGlobalMetadata(principalID, name string, description *string, expectedGeneration int, now time.Time) (View, error) {
	if err := protocol.ValidateSecretName(name); err != nil {
		return View{}, err
	}
	desc, err := optionalDescription(description)
	if err != nil {
		return View{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.globalByName(tx, principalID, name)
	if err != nil {
		return View{}, err
	}
	if current.State != "ACTIVE" || current.Generation != expectedGeneration {
		return View{}, ErrConflict
	}
	ms := now.UnixMilli()
	res, err := tx.Exec(`UPDATE global_secret_references
		SET description = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		nullIfEmpty(desc), ms, principalID, current.ID, expectedGeneration)
	if err != nil {
		return View{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return View{}, fmt.Errorf("global secret generation changed during metadata update")
	}
	if err := tx.Commit(); err != nil {
		return View{}, err
	}
	updated, err := s.globalByName(s.db, principalID, name)
	if err != nil {
		return View{}, err
	}
	s.record(principalID, "global_secret.updated", "global_secret", current.ID, updated.Generation, map[string]any{"version": current.Version})
	return updated, nil
}

// DeleteGlobal physically removes ciphertext.
func (s *Store) DeleteGlobal(principalID, name string, expectedGeneration int, now time.Time) (View, error) {
	if err := protocol.ValidateSecretNameShape(name); err != nil {
		return View{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.globalByName(tx, principalID, name)
	if err != nil {
		return View{}, err
	}
	if current.State != "ACTIVE" || current.Generation != expectedGeneration {
		return View{}, ErrConflict
	}
	if _, err := tx.Exec(`DELETE FROM global_secret_versions WHERE principal_id = ? AND secret_reference_id = ?`, principalID, current.ID); err != nil {
		return View{}, err
	}
	res, err := tx.Exec(`DELETE FROM global_secret_references WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		principalID, current.ID, expectedGeneration)
	if err != nil {
		return View{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return View{}, fmt.Errorf("global secret generation changed during deletion")
	}
	if err := tx.Commit(); err != nil {
		return View{}, err
	}
	ms := now.UnixMilli()
	updated := current
	updated.State = "DELETED"
	updated.Generation = current.Generation + 1
	updated.UpdatedAt = now
	updated.DeletedAt = &ms
	s.record(principalID, "global_secret.deleted", "global_secret", current.ID, updated.Generation, map[string]any{"version": updated.Version})
	return updated, nil
}

// BulkApplyGlobal creates or rotates 1–200 global secrets.
func (s *Store) BulkApplyGlobal(principalID string, items []BulkItem, now time.Time) ([]View, error) {
	if len(items) < 1 || len(items) > 200 {
		return nil, fmt.Errorf("bulk items must contain 1 to 200 entries")
	}
	out := make([]View, 0, len(items))
	for _, item := range items {
		var view View
		var err error
		switch item.Action {
		case "create":
			desc := ""
			if item.Description != nil {
				desc = *item.Description
			}
			view, err = s.CreateGlobal(principalID, item.Name, item.Value, 0, desc, item.Purpose, now)
		case "rotate":
			view, err = s.RotateGlobal(principalID, item.Name, item.Value, item.ExpectedGeneration, item.Description, now)
		default:
			return nil, fmt.Errorf("bulk action must be create or rotate")
		}
		if err != nil {
			return nil, err
		}
		out = append(out, view)
	}
	return out, nil
}
