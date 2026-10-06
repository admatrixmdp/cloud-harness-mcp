package metadata

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/audit"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

// ErrConflict is a generation or uniqueness miss, mapped to CONFLICT.
var ErrConflict = fmt.Errorf("conflict")

// ErrInvalidName is a trimmed name outside 1–100 characters.
var ErrInvalidName = fmt.Errorf("metadata name must contain 1 to 100 characters")

// Project is dashboard-visible project metadata.
type Project struct {
	ID         string
	Name       string
	State      string
	Generation int
	CreatedAt  int64
	UpdatedAt  int64
	DeletedAt  *int64
}

// PublicJSON is the runner/dashboard projection.
func (p Project) PublicJSON() map[string]any {
	return map[string]any{
		"id":         p.ID,
		"name":       p.Name,
		"state":      p.State,
		"generation": p.Generation,
		"createdAt":  p.CreatedAt,
		"updatedAt":  p.UpdatedAt,
		"deletedAt":  deletedAtValue(p.DeletedAt),
	}
}

// Environment is dashboard-visible environment metadata.
type Environment struct {
	Project
	ProjectID string
}

// PublicJSON is the runner/dashboard projection.
func (e Environment) PublicJSON() map[string]any {
	out := e.Project.PublicJSON()
	out["projectId"] = e.ProjectID
	return out
}

// Store keeps principal-scoped projects and environments in SQLite.
type Store struct {
	db    *sql.DB
	audit *audit.Store
}

// Open creates project/environment tables if missing.
func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("metadata store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  name TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'DELETED')),
  generation INTEGER NOT NULL CHECK (generation > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER,
  UNIQUE(principal_id, id),
  UNIQUE(principal_id, name)
);
CREATE INDEX IF NOT EXISTS projects_principal_updated ON projects(principal_id, updated_at DESC, id);
CREATE TABLE IF NOT EXISTS environments (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  name TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'DELETED')),
  generation INTEGER NOT NULL CHECK (generation > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER,
  UNIQUE(principal_id, id),
  UNIQUE(principal_id, project_id, name)
);
CREATE INDEX IF NOT EXISTS environments_principal_project ON environments(principal_id, project_id, updated_at DESC, id);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// WithAudit records project/environment mutations on the shared audit log.
func (s *Store) WithAudit(store *audit.Store) *Store {
	s.audit = store
	return s
}

func normalizeName(name string) (string, error) {
	value := strings.TrimSpace(name)
	if value == "" || len(value) > 100 {
		return "", ErrInvalidName
	}
	return value, nil
}

func deletedAtValue(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

func (s *Store) record(principalID, action, subjectType, subjectID string, generation int, details map[string]any) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Record(principalID, action, subjectType, subjectID, generation, details)
}

func scanProject(row scanner) (Project, error) {
	var p Project
	var deleted sql.NullInt64
	if err := row.Scan(&p.ID, &p.Name, &p.State, &p.Generation, &p.CreatedAt, &p.UpdatedAt, &deleted); err != nil {
		return Project{}, err
	}
	if deleted.Valid {
		v := deleted.Int64
		p.DeletedAt = &v
	}
	return p, nil
}

func scanEnvironment(row scanner) (Environment, error) {
	var e Environment
	var deleted sql.NullInt64
	if err := row.Scan(&e.ID, &e.ProjectID, &e.Name, &e.State, &e.Generation, &e.CreatedAt, &e.UpdatedAt, &deleted); err != nil {
		return Environment{}, err
	}
	if deleted.Valid {
		v := deleted.Int64
		e.DeletedAt = &v
	}
	return e, nil
}

type scanner interface {
	Scan(dest ...any) error
}

// ListProjects returns ACTIVE projects newest-first.
func (s *Store) ListProjects(principalID string) ([]Project, error) {
	rows, err := s.db.Query(`SELECT id, name, state, generation, created_at, updated_at, deleted_at
		FROM projects WHERE principal_id = ? AND state = 'ACTIVE' ORDER BY updated_at DESC, id`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Project, 0)
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreateProject inserts generation 1. expectedGeneration must be 0.
func (s *Store) CreateProject(principalID, name string, expectedGeneration int, now int64) (Project, error) {
	if expectedGeneration != 0 {
		return Project{}, ErrConflict
	}
	projectName, err := normalizeName(name)
	if err != nil {
		return Project{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Project{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM projects WHERE principal_id = ? AND name = ?`, principalID, projectName).Scan(&exists); err != sql.ErrNoRows {
		if err == nil {
			return Project{}, ErrConflict
		}
		return Project{}, err
	}
	id := protocol.NewOpaqueID(protocol.PrefixProject)
	if _, err := tx.Exec(`INSERT INTO projects
		(id, principal_id, name, state, generation, created_at, updated_at, deleted_at)
		VALUES (?, ?, ?, 'ACTIVE', 1, ?, ?, NULL)`, id, principalID, projectName, now, now); err != nil {
		return Project{}, err
	}
	if err := tx.Commit(); err != nil {
		return Project{}, err
	}
	s.record(principalID, "project.created", "project", id, 1, map[string]any{})
	return Project{ID: id, Name: projectName, State: "ACTIVE", Generation: 1, CreatedAt: now, UpdatedAt: now}, nil
}

// UpdateProject renames an ACTIVE project at the expected generation.
func (s *Store) UpdateProject(principalID, id, name string, expectedGeneration int, now int64) (Project, error) {
	if expectedGeneration < 1 {
		return Project{}, ErrConflict
	}
	projectName, err := normalizeName(name)
	if err != nil {
		return Project{}, err
	}
	res, err := s.db.Exec(`UPDATE projects SET name = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		projectName, now, principalID, id, expectedGeneration)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Project{}, ErrConflict
		}
		return Project{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return Project{}, ErrConflict
	}
	p, err := s.project(principalID, id)
	if err != nil {
		return Project{}, err
	}
	s.record(principalID, "project.updated", "project", id, p.Generation, map[string]any{})
	return p, nil
}

// DeleteProject physically removes the project and nested environments/secrets.
func (s *Store) DeleteProject(principalID, id string, expectedGeneration int, now int64) (Project, error) {
	if expectedGeneration < 1 {
		return Project{}, ErrConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Project{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.projectTx(tx, principalID, id)
	if err != nil {
		return Project{}, err
	}
	if current.State != "ACTIVE" || current.Generation != expectedGeneration {
		return Project{}, ErrConflict
	}
	envRows, err := tx.Query(`SELECT id FROM environments WHERE principal_id = ? AND project_id = ?`, principalID, id)
	if err != nil {
		return Project{}, err
	}
	var envIDs []string
	for envRows.Next() {
		var envID string
		if err := envRows.Scan(&envID); err != nil {
			envRows.Close()
			return Project{}, err
		}
		envIDs = append(envIDs, envID)
	}
	envRows.Close()
	if err := envRows.Err(); err != nil {
		return Project{}, err
	}
	for _, envID := range envIDs {
		if err := removeEnvironmentRecords(tx, principalID, envID); err != nil {
			return Project{}, err
		}
	}
	res, err := tx.Exec(`DELETE FROM projects WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		principalID, id, expectedGeneration)
	if err != nil {
		return Project{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return Project{}, fmt.Errorf("project generation changed during deletion")
	}
	if err := tx.Commit(); err != nil {
		return Project{}, err
	}
	deleted := now
	value := Project{
		ID: current.ID, Name: current.Name, State: "DELETED", Generation: current.Generation + 1,
		CreatedAt: current.CreatedAt, UpdatedAt: now, DeletedAt: &deleted,
	}
	s.record(principalID, "project.deleted", "project", id, value.Generation, map[string]any{})
	return value, nil
}

// ListEnvironments returns ACTIVE environments for an ACTIVE project.
func (s *Store) ListEnvironments(principalID, projectID string) ([]Environment, error) {
	rows, err := s.db.Query(`SELECT environments.id, environments.project_id, environments.name, environments.state,
		environments.generation, environments.created_at, environments.updated_at, environments.deleted_at
		FROM environments
		JOIN projects ON projects.principal_id = environments.principal_id AND projects.id = environments.project_id
		WHERE environments.principal_id = ? AND environments.project_id = ?
			AND environments.state = 'ACTIVE' AND projects.state = 'ACTIVE'
		ORDER BY environments.updated_at DESC, environments.id`, principalID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Environment, 0)
	for rows.Next() {
		e, err := scanEnvironment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CreateEnvironment inserts generation 1 under an ACTIVE project.
func (s *Store) CreateEnvironment(principalID, projectID, name string, expectedGeneration int, now int64) (Environment, error) {
	if expectedGeneration != 0 {
		return Environment{}, ErrConflict
	}
	environmentName, err := normalizeName(name)
	if err != nil {
		return Environment{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Environment{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM projects WHERE principal_id = ? AND id = ? AND state = 'ACTIVE'`, principalID, projectID).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return Environment{}, ErrConflict
		}
		return Environment{}, err
	}
	if err := tx.QueryRow(`SELECT 1 FROM environments WHERE principal_id = ? AND project_id = ? AND name = ?`,
		principalID, projectID, environmentName).Scan(&exists); err != sql.ErrNoRows {
		if err == nil {
			return Environment{}, ErrConflict
		}
		return Environment{}, err
	}
	id := protocol.NewOpaqueID(protocol.PrefixEnvironment)
	if _, err := tx.Exec(`INSERT INTO environments
		(id, principal_id, project_id, name, state, generation, created_at, updated_at, deleted_at)
		VALUES (?, ?, ?, ?, 'ACTIVE', 1, ?, ?, NULL)`, id, principalID, projectID, environmentName, now, now); err != nil {
		return Environment{}, err
	}
	if err := tx.Commit(); err != nil {
		return Environment{}, err
	}
	s.record(principalID, "environment.created", "environment", id, 1, map[string]any{"projectId": projectID})
	return Environment{
		Project:   Project{ID: id, Name: environmentName, State: "ACTIVE", Generation: 1, CreatedAt: now, UpdatedAt: now},
		ProjectID: projectID,
	}, nil
}

// UpdateEnvironment renames an ACTIVE environment at the expected generation.
func (s *Store) UpdateEnvironment(principalID, id, name string, expectedGeneration int, now int64) (Environment, error) {
	if expectedGeneration < 1 {
		return Environment{}, ErrConflict
	}
	environmentName, err := normalizeName(name)
	if err != nil {
		return Environment{}, err
	}
	if _, err := s.ActiveEnvironment(principalID, id); err != nil {
		return Environment{}, err
	}
	res, err := s.db.Exec(`UPDATE environments SET name = ?, generation = generation + 1, updated_at = ?
		WHERE principal_id = ? AND id = ? AND generation = ? AND state = 'ACTIVE'`,
		environmentName, now, principalID, id, expectedGeneration)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Environment{}, ErrConflict
		}
		return Environment{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return Environment{}, ErrConflict
	}
	e, err := s.environment(principalID, id)
	if err != nil {
		return Environment{}, err
	}
	s.record(principalID, "environment.updated", "environment", id, e.Generation, map[string]any{})
	return e, nil
}

// DeleteEnvironment physically removes the environment and nested secrets.
func (s *Store) DeleteEnvironment(principalID, id string, expectedGeneration int, now int64) (Environment, error) {
	if expectedGeneration < 1 {
		return Environment{}, ErrConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Environment{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.activeEnvironmentTx(tx, principalID, id)
	if err != nil {
		return Environment{}, err
	}
	if current.Generation != expectedGeneration {
		return Environment{}, ErrConflict
	}
	if err := removeEnvironmentRecords(tx, principalID, id); err != nil {
		return Environment{}, err
	}
	if err := tx.Commit(); err != nil {
		return Environment{}, err
	}
	deleted := now
	value := Environment{
		Project: Project{
			ID: current.ID, Name: current.Name, State: "DELETED", Generation: current.Generation + 1,
			CreatedAt: current.CreatedAt, UpdatedAt: now, DeletedAt: &deleted,
		},
		ProjectID: current.ProjectID,
	}
	s.record(principalID, "environment.deleted", "environment", id, value.Generation, map[string]any{})
	return value, nil
}

// HasActiveEnvironment reports whether env belongs to an ACTIVE project.
func (s *Store) HasActiveEnvironment(principalID, environmentID string) bool {
	_, err := s.ActiveEnvironment(principalID, environmentID)
	return err == nil
}

// ActiveEnvironment returns an ACTIVE environment under an ACTIVE project.
func (s *Store) ActiveEnvironment(principalID, id string) (Environment, error) {
	row := s.db.QueryRow(`SELECT env.id, env.project_id, env.name, env.state, env.generation, env.created_at, env.updated_at, env.deleted_at
		FROM environments env
		JOIN projects ON projects.principal_id = env.principal_id AND projects.id = env.project_id
		WHERE env.principal_id = ? AND env.id = ? AND env.state = 'ACTIVE' AND projects.state = 'ACTIVE'`, principalID, id)
	e, err := scanEnvironment(row)
	if err == sql.ErrNoRows {
		return Environment{}, ErrConflict
	}
	return e, err
}

func (s *Store) project(principalID, id string) (Project, error) {
	row := s.db.QueryRow(`SELECT id, name, state, generation, created_at, updated_at, deleted_at
		FROM projects WHERE principal_id = ? AND id = ?`, principalID, id)
	p, err := scanProject(row)
	if err == sql.ErrNoRows {
		return Project{}, ErrConflict
	}
	return p, err
}

func (s *Store) projectTx(tx *sql.Tx, principalID, id string) (Project, error) {
	row := tx.QueryRow(`SELECT id, name, state, generation, created_at, updated_at, deleted_at
		FROM projects WHERE principal_id = ? AND id = ?`, principalID, id)
	p, err := scanProject(row)
	if err == sql.ErrNoRows {
		return Project{}, ErrConflict
	}
	return p, err
}

func (s *Store) environment(principalID, id string) (Environment, error) {
	row := s.db.QueryRow(`SELECT id, project_id, name, state, generation, created_at, updated_at, deleted_at
		FROM environments WHERE principal_id = ? AND id = ?`, principalID, id)
	e, err := scanEnvironment(row)
	if err == sql.ErrNoRows {
		return Environment{}, ErrConflict
	}
	return e, err
}

func (s *Store) activeEnvironmentTx(tx *sql.Tx, principalID, id string) (Environment, error) {
	row := tx.QueryRow(`SELECT env.id, env.project_id, env.name, env.state, env.generation, env.created_at, env.updated_at, env.deleted_at
		FROM environments env
		JOIN projects ON projects.principal_id = env.principal_id AND projects.id = env.project_id
		WHERE env.principal_id = ? AND env.id = ? AND env.state = 'ACTIVE' AND projects.state = 'ACTIVE'`, principalID, id)
	e, err := scanEnvironment(row)
	if err == sql.ErrNoRows {
		return Environment{}, ErrConflict
	}
	return e, err
}

func removeEnvironmentRecords(tx *sql.Tx, principalID, environmentID string) error {
	if err := execIgnoreMissing(tx, `DELETE FROM secret_versions WHERE principal_id = ? AND secret_reference_id IN
		(SELECT id FROM secret_references WHERE principal_id = ? AND environment_id = ?)`,
		principalID, principalID, environmentID); err != nil {
		return err
	}
	if err := execIgnoreMissing(tx, `DELETE FROM secret_references WHERE principal_id = ? AND environment_id = ?`,
		principalID, environmentID); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM environments WHERE principal_id = ? AND id = ?`, principalID, environmentID)
	return err
}

func execIgnoreMissing(tx *sql.Tx, query string, args ...any) error {
	_, err := tx.Exec(query, args...)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return nil
	}
	return err
}
