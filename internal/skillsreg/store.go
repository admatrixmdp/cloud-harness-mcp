package skillsreg

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = fmt.Errorf("not found")
	ErrConflict = fmt.Errorf("conflict")
	ErrInvalid  = fmt.Errorf("invalid")
)

var slugRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)
var skillNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)

var allowedKinds = map[string]struct{}{"built-in": {}, "owner": {}, "workspace": {}, "repository": {}, "registry": {}}
var allowedProviders = map[string]struct{}{"skills-sh": {}, "skillx": {}, "git": {}, "custom": {}}
var allowedStates = map[string]struct{}{"enabled": {}, "disabled": {}, "archived": {}}
var allowedOrigins = map[string]struct{}{"import": {}, "refresh": {}, "edit": {}, "restore": {}, "fork": {}}
var allowedImportKinds = map[string]struct{}{"skills-sh": {}, "skillx": {}, "git": {}}
var allowedTransitions = map[string][]string{
	"enabled":  {"enabled", "disabled", "archived"},
	"disabled": {"disabled", "enabled", "archived"},
	"archived": {"archived"},
}

// Source is dashboard-visible skill metadata. Bundle bytes never appear.
type Source struct {
	ID                string
	Slug              string
	DisplayName       string
	Description       string
	Kind              string
	Provider          any
	SourceRef         any
	CurrentRevisionID any
	State             string
	Tags              []string
	Generation        int
	CreatedAt         int64
	UpdatedAt         int64
	Version           any
}

func (s Source) PublicJSON() map[string]any {
	out := map[string]any{
		"id":                s.ID,
		"slug":              s.Slug,
		"displayName":       s.DisplayName,
		"description":       s.Description,
		"kind":              s.Kind,
		"provider":          s.Provider,
		"sourceRef":         s.SourceRef,
		"currentRevisionId": s.CurrentRevisionID,
		"state":             s.State,
		"tags":              s.Tags,
		"generation":        s.Generation,
		"createdAt":         s.CreatedAt,
		"updatedAt":         s.UpdatedAt,
	}
	if s.Version != nil {
		out["version"] = s.Version
	}
	return out
}

// Revision is an immutable skill revision. Bundle path is never projected.
type Revision struct {
	ID                  string
	SkillSourceID       string
	ParentRevisionID    any
	Origin              string
	BundleSHA256        string
	ContentSHA256       string
	HasExecutableAssets bool
	CreatedAt           int64
	Version             any
}

func (r Revision) PublicJSON() map[string]any {
	out := map[string]any{
		"id":                  r.ID,
		"skillSourceId":       r.SkillSourceID,
		"parentRevisionId":    r.ParentRevisionID,
		"origin":              r.Origin,
		"hasExecutableAssets": r.HasExecutableAssets,
		"createdAt":           r.CreatedAt,
	}
	if r.Version != nil {
		out["version"] = r.Version
	}
	return out
}

// Set is a named collection of pinned skill revisions.
type Set struct {
	ID          string
	Name        string
	Description string
	Generation  int
	CreatedAt   int64
	UpdatedAt   int64
	Items       []SetItem
}

type SetItem struct {
	SkillSetID    string
	Ordinal       int
	SkillSourceID string
	RevisionID    string
	Name          string
}

func (s Set) PublicJSON() map[string]any {
	return map[string]any{
		"id":          s.ID,
		"name":        s.Name,
		"description": s.Description,
		"generation":  s.Generation,
		"createdAt":   s.CreatedAt,
		"updatedAt":   s.UpdatedAt,
	}
}

func (s Set) PublicGetJSON() map[string]any {
	out := s.PublicJSON()
	items := make([]map[string]any, 0, len(s.Items))
	for _, item := range s.Items {
		items = append(items, map[string]any{
			"skillSetId":    s.ID,
			"ordinal":       item.Ordinal,
			"skillSourceId": item.SkillSourceID,
			"revisionId":    item.RevisionID,
			"name":          item.Name,
		})
	}
	out["items"] = items
	return out
}

// ImportJob is a queued import. Remote fetch is not performed in this slice.
type ImportJob struct {
	ID              string
	SourceKind      string
	SourceRef       string
	State           string
	Progress        map[string]any
	Result          any
	ErrorCode       any
	SkillRevisionID any
	CreatedAt       int64
	UpdatedAt       int64
}

func (j ImportJob) PublicJSON() map[string]any {
	progress := j.Progress
	if progress == nil {
		progress = map[string]any{}
	}
	return map[string]any{
		"id":              j.ID,
		"sourceKind":      j.SourceKind,
		"sourceRef":       j.SourceRef,
		"state":           j.State,
		"progress":        progress,
		"result":          j.Result,
		"errorCode":       j.ErrorCode,
		"skillRevisionId": j.SkillRevisionID,
		"createdAt":       j.CreatedAt,
		"updatedAt":       j.UpdatedAt,
	}
}

// Store persists skill sources, immutable revisions, sets, and import jobs.
type Store struct {
	db *sql.DB
}

// Open creates skill tables if missing.
func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("skill store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS skill_sources (
  owner_id TEXT NOT NULL,
  id TEXT NOT NULL,
  slug TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL CHECK (kind IN ('built-in','owner','workspace','repository','registry')),
  provider TEXT CHECK (provider IN ('skills-sh','skillx','git','custom')),
  source_ref TEXT,
  current_revision_id TEXT,
  state TEXT NOT NULL DEFAULT 'enabled' CHECK (state IN ('enabled','disabled','archived')),
  tags TEXT NOT NULL DEFAULT '[]',
  generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (owner_id, id),
  UNIQUE (owner_id, slug)
);
CREATE TABLE IF NOT EXISTS skill_revisions (
  owner_id TEXT NOT NULL,
  skill_source_id TEXT NOT NULL,
  id TEXT NOT NULL,
  parent_revision_id TEXT,
  origin TEXT NOT NULL CHECK (origin IN ('import','refresh','edit','restore','fork')),
  bundle_sha256 TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  has_executable_assets INTEGER NOT NULL DEFAULT 0 CHECK (has_executable_assets IN (0,1)),
  created_at INTEGER NOT NULL,
  version TEXT,
  PRIMARY KEY (owner_id, id),
  UNIQUE (owner_id, skill_source_id, id)
);
CREATE INDEX IF NOT EXISTS skill_revisions_source_idx ON skill_revisions(owner_id, skill_source_id, created_at DESC);
CREATE TABLE IF NOT EXISTS skill_sets (
  owner_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (owner_id, id)
);
CREATE TABLE IF NOT EXISTS skill_set_items (
  owner_id TEXT NOT NULL,
  skill_set_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  skill_source_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (owner_id, skill_set_id, ordinal),
  UNIQUE (owner_id, skill_set_id, name)
);
CREATE TABLE IF NOT EXISTS workspace_skill_set_snapshots (
  owner_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  skill_set_id TEXT NOT NULL,
  skill_set_generation INTEGER NOT NULL,
  snapshot_sha256 TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner_id, workspace_id, ordinal)
);
CREATE TABLE IF NOT EXISTS workspace_skill_assignments (
  owner_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  name TEXT NOT NULL,
  skill_source_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  tier TEXT NOT NULL,
  pinned INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (owner_id, workspace_id, ordinal)
);
CREATE TABLE IF NOT EXISTS skill_import_jobs (
  owner_id TEXT NOT NULL,
  id TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('skills-sh','skillx','git')),
  source_ref TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued','running','succeeded','failed','cancelled')),
  progress_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT,
  error_code TEXT,
  skill_revision_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (owner_id, id)
);
CREATE INDEX IF NOT EXISTS skill_import_jobs_state_idx ON skill_import_jobs(owner_id, state, updated_at DESC);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizeName(value string, max int) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > max {
		return "", fmt.Errorf("%w: name is invalid", ErrInvalid)
	}
	return trimmed, nil
}

func normalizeTags(tags []string) ([]string, error) {
	if len(tags) > 16 {
		return nil, fmt.Errorf("%w: at most 16 tags", ErrInvalid)
	}
	out := make([]string, 0, len(tags))
	seen := map[string]struct{}{}
	for _, tag := range tags {
		value := strings.TrimSpace(tag)
		if value == "" || len(value) > 32 {
			return nil, fmt.Errorf("%w: tag is invalid", ErrInvalid)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func parseTags(raw string) []string {
	var tags []string
	if err := json.Unmarshal([]byte(raw), &tags); err != nil || tags == nil {
		return []string{}
	}
	return tags
}

func (s *Store) requireGeneration(table, ownerID, id string, expected int) error {
	query := "SELECT generation FROM skill_sources WHERE owner_id = ? AND id = ?"
	if table == "skill_sets" {
		query = "SELECT generation FROM skill_sets WHERE owner_id = ? AND id = ?"
	}
	var generation int
	err := s.db.QueryRow(query, ownerID, id).Scan(&generation)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if generation != expected {
		return ErrConflict
	}
	return nil
}

// CreateCustom writes a custom owner skill. Instructions are digested; plaintext is not stored.
func (s *Store) CreateCustom(ownerID, slug, displayName, description, instructions string, tags []string, hasExecutable bool, version string, now int64) (Source, error) {
	if !slugRe.MatchString(slug) {
		return Source{}, fmt.Errorf("%w: slug is invalid", ErrInvalid)
	}
	displayName, err := normalizeName(displayName, 100)
	if err != nil {
		return Source{}, err
	}
	if strings.Contains(instructions, "\x00") || len(instructions) < 1 || len(instructions) > 65_536 {
		return Source{}, fmt.Errorf("%w: instructions are invalid", ErrInvalid)
	}
	if len(description) > 2_000 {
		return Source{}, fmt.Errorf("%w: description is too long", ErrInvalid)
	}
	tags, err = normalizeTags(tags)
	if err != nil {
		return Source{}, err
	}
	sourceID := protocol.NewOpaqueID(protocol.PrefixSkillSource)
	revisionID := protocol.NewOpaqueID(protocol.PrefixSkillRevision)
	content := digest(instructions)
	tagJSON, _ := json.Marshal(tags)
	tx, err := s.db.Begin()
	if err != nil {
		return Source{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO skill_sources
		(owner_id, id, slug, display_name, description, kind, provider, source_ref, current_revision_id, state, tags, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'owner', 'custom', NULL, NULL, 'enabled', ?, 1, ?, ?)`,
		ownerID, sourceID, slug, displayName, description, string(tagJSON), now, now); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Source{}, ErrConflict
		}
		return Source{}, err
	}
	var versionVal any
	if version != "" {
		versionVal = version
	}
	if _, err := tx.Exec(`INSERT INTO skill_revisions
		(owner_id, skill_source_id, id, parent_revision_id, origin, bundle_sha256, content_sha256, has_executable_assets, created_at, version)
		VALUES (?, ?, ?, NULL, 'edit', ?, ?, ?, ?, ?)`,
		ownerID, sourceID, revisionID, content, content, boolToInt(hasExecutable), now, versionVal); err != nil {
		return Source{}, err
	}
	if _, err := tx.Exec(`UPDATE skill_sources SET current_revision_id = ? WHERE owner_id = ? AND id = ?`, revisionID, ownerID, sourceID); err != nil {
		return Source{}, err
	}
	if err := tx.Commit(); err != nil {
		return Source{}, err
	}
	src, err := s.Get(ownerID, sourceID)
	if err != nil {
		return Source{}, err
	}
	return src, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) Get(ownerID, id string) (Source, error) {
	var src Source
	var provider, sourceRef, current, version sql.NullString
	var tags string
	err := s.db.QueryRow(`SELECT skill_sources.id, skill_sources.slug, skill_sources.display_name, skill_sources.description,
		skill_sources.kind, skill_sources.provider, skill_sources.source_ref, skill_sources.current_revision_id,
		skill_sources.state, skill_sources.tags, skill_sources.generation, skill_sources.created_at, skill_sources.updated_at,
		skill_revisions.version
		FROM skill_sources
		LEFT JOIN skill_revisions ON skill_revisions.owner_id = skill_sources.owner_id AND skill_revisions.id = skill_sources.current_revision_id
		WHERE skill_sources.owner_id = ? AND skill_sources.id = ?`, ownerID, id).
		Scan(&src.ID, &src.Slug, &src.DisplayName, &src.Description, &src.Kind, &provider, &sourceRef, &current,
			&src.State, &tags, &src.Generation, &src.CreatedAt, &src.UpdatedAt, &version)
	if err == sql.ErrNoRows {
		return Source{}, ErrNotFound
	}
	if err != nil {
		return Source{}, err
	}
	src.Tags = parseTags(tags)
	if provider.Valid {
		src.Provider = provider.String
	}
	if sourceRef.Valid {
		src.SourceRef = sourceRef.String
	}
	if current.Valid {
		src.CurrentRevisionID = current.String
	}
	if version.Valid {
		src.Version = version.String
	}
	return src, nil
}

// List returns newest-first sources with optional filters.
func (s *Store) List(ownerID, state, kind, provider string, limit int) ([]Source, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id FROM skill_sources
		WHERE owner_id = ?
		  AND (? = '' OR state = ?)
		  AND (? = '' OR kind = ?)
		  AND (? = '' OR provider = ?)
		ORDER BY updated_at DESC LIMIT ?`,
		ownerID, state, state, kind, kind, provider, provider, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Source, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		src, err := s.Get(ownerID, id)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

func (s *Store) ListRevisions(ownerID, skillID string, limit int) ([]Revision, error) {
	if _, err := s.Get(ownerID, skillID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, skill_source_id, parent_revision_id, origin, bundle_sha256, content_sha256, has_executable_assets, created_at, version
		FROM skill_revisions WHERE owner_id = ? AND skill_source_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`,
		ownerID, skillID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Revision, 0)
	for rows.Next() {
		rev, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRevision(row rowScanner) (Revision, error) {
	var rev Revision
	var parent, version sql.NullString
	var exec int
	if err := row.Scan(&rev.ID, &rev.SkillSourceID, &parent, &rev.Origin, &rev.BundleSHA256, &rev.ContentSHA256, &exec, &rev.CreatedAt, &version); err != nil {
		return Revision{}, err
	}
	rev.HasExecutableAssets = exec == 1
	if parent.Valid {
		rev.ParentRevisionID = parent.String
	}
	if version.Valid {
		rev.Version = version.String
	}
	return rev, nil
}

func (s *Store) GetRevision(ownerID, skillID, revisionID string) (Revision, error) {
	row := s.db.QueryRow(`SELECT id, skill_source_id, parent_revision_id, origin, bundle_sha256, content_sha256, has_executable_assets, created_at, version
		FROM skill_revisions WHERE owner_id = ? AND skill_source_id = ? AND id = ?`, ownerID, skillID, revisionID)
	rev, err := scanRevision(row)
	if err == sql.ErrNoRows {
		return Revision{}, ErrNotFound
	}
	return rev, err
}

func (s *Store) SetState(ownerID, id, state string, expectedGeneration int, now int64) (Source, error) {
	if _, ok := allowedStates[state]; !ok {
		return Source{}, fmt.Errorf("%w: unsupported state", ErrInvalid)
	}
	if err := s.requireGeneration("skill_sources", ownerID, id, expectedGeneration); err != nil {
		return Source{}, err
	}
	current, err := s.Get(ownerID, id)
	if err != nil {
		return Source{}, err
	}
	allowed := allowedTransitions[current.State]
	ok := false
	for _, next := range allowed {
		if next == state {
			ok = true
			break
		}
	}
	if !ok {
		return Source{}, fmt.Errorf("%w: cannot move skill from %s to %s", ErrInvalid, current.State, state)
	}
	if _, err := s.db.Exec(`UPDATE skill_sources SET state = ?, generation = generation + 1, updated_at = ? WHERE owner_id = ? AND id = ?`,
		state, now, ownerID, id); err != nil {
		return Source{}, err
	}
	return s.Get(ownerID, id)
}

func (s *Store) UpdateMetadata(ownerID, id string, expectedGeneration int, displayName, description *string, tags []string, tagsSet bool, now int64) (Source, error) {
	if err := s.requireGeneration("skill_sources", ownerID, id, expectedGeneration); err != nil {
		return Source{}, err
	}
	var nameVal, descVal, tagVal any
	if displayName != nil {
		name, err := normalizeName(*displayName, 100)
		if err != nil {
			return Source{}, err
		}
		nameVal = name
	}
	if description != nil {
		if len(*description) > 2_000 {
			return Source{}, fmt.Errorf("%w: description is too long", ErrInvalid)
		}
		descVal = *description
	}
	if tagsSet {
		normalized, err := normalizeTags(tags)
		if err != nil {
			return Source{}, err
		}
		raw, _ := json.Marshal(normalized)
		tagVal = string(raw)
	}
	if _, err := s.db.Exec(`UPDATE skill_sources SET
		display_name = COALESCE(?, display_name),
		description = COALESCE(?, description),
		tags = COALESCE(?, tags),
		generation = generation + 1,
		updated_at = ?
		WHERE owner_id = ? AND id = ?`, nameVal, descVal, tagVal, now, ownerID, id); err != nil {
		return Source{}, err
	}
	return s.Get(ownerID, id)
}

func (s *Store) AddRevision(ownerID, skillID, bundle, content, origin string, parent any, hasExec bool, expectedGeneration int, version any, now int64) (string, error) {
	if _, ok := allowedOrigins[origin]; !ok {
		return "", fmt.Errorf("%w: unsupported origin", ErrInvalid)
	}
	if err := s.requireGeneration("skill_sources", ownerID, skillID, expectedGeneration); err != nil {
		return "", err
	}
	id := protocol.NewOpaqueID(protocol.PrefixSkillRevision)
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO skill_revisions
		(owner_id, skill_source_id, id, parent_revision_id, origin, bundle_sha256, content_sha256, has_executable_assets, created_at, version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ownerID, skillID, id, parent, origin, bundle, content, boolToInt(hasExec), now, version); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE skill_sources SET current_revision_id = ?, generation = generation + 1, updated_at = ? WHERE owner_id = ? AND id = ?`,
		id, now, ownerID, skillID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) Restore(ownerID, skillID, revisionID string, expectedGeneration int, now int64) (Source, error) {
	rev, err := s.GetRevision(ownerID, skillID, revisionID)
	if err != nil {
		return Source{}, err
	}
	if _, err := s.AddRevision(ownerID, skillID, rev.BundleSHA256, rev.ContentSHA256, "restore", rev.ID, rev.HasExecutableAssets, expectedGeneration, rev.Version, now); err != nil {
		return Source{}, err
	}
	return s.Get(ownerID, skillID)
}

func (s *Store) Fork(ownerID, skillID, revisionID, slug, displayName string, now int64) (Source, map[string]any, error) {
	rev, err := s.GetRevision(ownerID, skillID, revisionID)
	if err != nil {
		return Source{}, nil, err
	}
	src, err := s.Get(ownerID, skillID)
	if err != nil {
		return Source{}, nil, err
	}
	created, err := s.CreateCustom(ownerID, slug, displayName, src.Description, "fork", src.Tags, rev.HasExecutableAssets, "", now)
	if err != nil {
		return Source{}, nil, err
	}
	// Replace the placeholder revision hashes with the forked bytes.
	if _, err := s.db.Exec(`UPDATE skill_revisions SET origin = 'fork', bundle_sha256 = ?, content_sha256 = ? WHERE owner_id = ? AND id = ?`,
		rev.BundleSHA256, rev.ContentSHA256, ownerID, created.CurrentRevisionID); err != nil {
		return Source{}, nil, err
	}
	out, err := s.Get(ownerID, created.ID)
	if err != nil {
		return Source{}, nil, err
	}
	return out, map[string]any{"skillId": src.ID, "revisionId": rev.ID}, nil
}

func (s *Store) CreateEdit(ownerID, skillID, instructions, version string, expectedGeneration int, now int64) (string, error) {
	src, err := s.Get(ownerID, skillID)
	if err != nil {
		return "", err
	}
	if strings.Contains(instructions, "\x00") || len(instructions) < 1 || len(instructions) > 200_000 {
		return "", fmt.Errorf("%w: instructions are invalid", ErrInvalid)
	}
	content := digest(instructions)
	var versionVal any
	if version != "" {
		versionVal = version
	}
	_ = src
	return s.AddRevision(ownerID, skillID, content, content, "edit", src.CurrentRevisionID, false, expectedGeneration, versionVal, now)
}

func (s *Store) Usage(ownerID, skillID string) (map[string]any, error) {
	if _, err := s.Get(ownerID, skillID); err != nil {
		return nil, err
	}
	setRows, err := s.db.Query(`SELECT DISTINCT i.skill_set_id, s.name FROM skill_set_items i
		JOIN skill_sets s ON s.owner_id = i.owner_id AND s.id = i.skill_set_id
		WHERE i.owner_id = ? AND i.skill_source_id = ? ORDER BY s.name`, ownerID, skillID)
	if err != nil {
		return nil, err
	}
	defer setRows.Close()
	sets := make([]map[string]any, 0)
	for setRows.Next() {
		var id, name string
		if err := setRows.Scan(&id, &name); err != nil {
			return nil, err
		}
		sets = append(sets, map[string]any{"skillSetId": id, "name": name})
	}
	wsRows, err := s.db.Query(`SELECT DISTINCT a.workspace_id, a.name, a.revision_id FROM workspace_skill_assignments a
		WHERE a.owner_id = ? AND a.skill_source_id = ? ORDER BY a.workspace_id`, ownerID, skillID)
	if err != nil {
		return nil, err
	}
	defer wsRows.Close()
	live := make([]map[string]any, 0)
	for wsRows.Next() {
		var id, name, rev string
		if err := wsRows.Scan(&id, &name, &rev); err != nil {
			return nil, err
		}
		live = append(live, map[string]any{"workspaceId": id, "status": "ACTIVE", "name": name, "revisionId": rev})
	}
	return map[string]any{"sets": sets, "liveWorkspaces": live}, nil
}

func (s *Store) SearchLocal(ownerID, query string, limit int) ([]Source, error) {
	if query == "" || len(query) > 200 {
		return nil, fmt.Errorf("%w: query is invalid", ErrInvalid)
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	all, err := s.List(ownerID, "", "", "", 200)
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(query)
	out := make([]Source, 0)
	for _, src := range all {
		if strings.Contains(strings.ToLower(src.Slug), needle) || strings.Contains(strings.ToLower(src.DisplayName), needle) {
			out = append(out, src)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *Store) CreateSet(ownerID, name, description string, items []SetItem, now int64) (Set, error) {
	name, err := normalizeName(name, 100)
	if err != nil {
		return Set{}, err
	}
	if len(description) > 2_000 {
		return Set{}, fmt.Errorf("%w: description is too long", ErrInvalid)
	}
	if len(items) > 128 {
		return Set{}, fmt.Errorf("%w: at most 128 items", ErrInvalid)
	}
	id := protocol.NewOpaqueID(protocol.PrefixSkillSet)
	tx, err := s.db.Begin()
	if err != nil {
		return Set{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO skill_sets (owner_id, id, name, description, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, ?, ?)`, ownerID, id, name, description, now, now); err != nil {
		return Set{}, err
	}
	if err := replaceItems(tx, ownerID, id, items); err != nil {
		return Set{}, err
	}
	if err := tx.Commit(); err != nil {
		return Set{}, err
	}
	return s.GetSet(ownerID, id)
}

func replaceItems(tx *sql.Tx, ownerID, setID string, items []SetItem) error {
	if _, err := tx.Exec(`DELETE FROM skill_set_items WHERE owner_id = ? AND skill_set_id = ?`, ownerID, setID); err != nil {
		return err
	}
	for i, item := range items {
		if !protocol.ValidOpaqueID(protocol.PrefixSkillSource, item.SkillSourceID) || !protocol.ValidOpaqueID(protocol.PrefixSkillRevision, item.RevisionID) {
			return fmt.Errorf("%w: skill set item identifiers are invalid", ErrInvalid)
		}
		if !skillNameRe.MatchString(item.Name) {
			return fmt.Errorf("%w: skill set item name is invalid", ErrInvalid)
		}
		if _, err := tx.Exec(`INSERT INTO skill_set_items (owner_id, skill_set_id, ordinal, skill_source_id, revision_id, name)
			VALUES (?, ?, ?, ?, ?, ?)`, ownerID, setID, i, item.SkillSourceID, item.RevisionID, item.Name); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetSet(ownerID, id string) (Set, error) {
	var set Set
	err := s.db.QueryRow(`SELECT id, name, description, generation, created_at, updated_at FROM skill_sets WHERE owner_id = ? AND id = ?`,
		ownerID, id).Scan(&set.ID, &set.Name, &set.Description, &set.Generation, &set.CreatedAt, &set.UpdatedAt)
	if err == sql.ErrNoRows {
		return Set{}, ErrNotFound
	}
	if err != nil {
		return Set{}, err
	}
	rows, err := s.db.Query(`SELECT ordinal, skill_source_id, revision_id, name FROM skill_set_items WHERE owner_id = ? AND skill_set_id = ? ORDER BY ordinal`,
		ownerID, id)
	if err != nil {
		return Set{}, err
	}
	defer rows.Close()
	set.Items = make([]SetItem, 0)
	for rows.Next() {
		var item SetItem
		if err := rows.Scan(&item.Ordinal, &item.SkillSourceID, &item.RevisionID, &item.Name); err != nil {
			return Set{}, err
		}
		item.SkillSetID = set.ID
		set.Items = append(set.Items, item)
	}
	return set, rows.Err()
}

func (s *Store) ListSets(ownerID string, limit int) ([]Set, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id FROM skill_sets WHERE owner_id = ? ORDER BY updated_at DESC LIMIT ?`, ownerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Set, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		set, err := s.GetSet(ownerID, id)
		if err != nil {
			return nil, err
		}
		out = append(out, set)
	}
	return out, rows.Err()
}

func (s *Store) UpdateSet(ownerID, id string, expectedGeneration int, name, description *string, items []SetItem, itemsSet bool, now int64) (Set, error) {
	if err := s.requireGeneration("skill_sets", ownerID, id, expectedGeneration); err != nil {
		return Set{}, err
	}
	var nameVal, descVal any
	if name != nil {
		normalized, err := normalizeName(*name, 100)
		if err != nil {
			return Set{}, err
		}
		nameVal = normalized
	}
	if description != nil {
		if len(*description) > 2_000 {
			return Set{}, fmt.Errorf("%w: description is too long", ErrInvalid)
		}
		descVal = *description
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Set{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE skill_sets SET name = COALESCE(?, name), description = COALESCE(?, description), generation = generation + 1, updated_at = ?
		WHERE owner_id = ? AND id = ?`, nameVal, descVal, now, ownerID, id); err != nil {
		return Set{}, err
	}
	if itemsSet {
		if err := replaceItems(tx, ownerID, id, items); err != nil {
			return Set{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Set{}, err
	}
	return s.GetSet(ownerID, id)
}

func (s *Store) DeleteSet(ownerID, id string, expectedGeneration int) error {
	if err := s.requireGeneration("skill_sets", ownerID, id, expectedGeneration); err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM workspace_skill_set_snapshots WHERE owner_id = ? AND skill_set_id = ?`, ownerID, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: skill set is referenced by workspace snapshot(s)", ErrConflict)
	}
	_, err := s.db.Exec(`DELETE FROM skill_sets WHERE owner_id = ? AND id = ?`, ownerID, id)
	return err
}

type PreviewRequest struct {
	SkillSetID         string
	ExpectedGeneration int
}

func (s *Store) Preview(ownerID string, requested []PreviewRequest, overrides map[string]string) (map[string]any, error) {
	sources, err := s.List(ownerID, "", "", "", 200)
	if err != nil {
		return nil, err
	}
	byID := map[string]Source{}
	for _, src := range sources {
		byID[src.ID] = src
	}
	candidates := make([]candidateLike, 0)
	generation := 0
	for _, req := range requested {
		set, err := s.GetSet(ownerID, req.SkillSetID)
		if err != nil {
			return nil, err
		}
		if set.Generation != req.ExpectedGeneration {
			return nil, ErrConflict
		}
		if set.Generation > generation {
			generation = set.Generation
		}
		for _, item := range set.Items {
			src, ok := byID[item.SkillSourceID]
			kind := "owner"
			state := "enabled"
			if ok {
				kind = src.Kind
				state = src.State
			}
			tier := kind
			if kind == "registry" {
				tier = "owner"
			}
			candidates = append(candidates, candidateLike{
				Name: item.Name, Tier: tier, SourceID: item.SkillSourceID, RevisionID: item.RevisionID,
				ContentSHA256: item.RevisionID, State: state,
			})
		}
	}
	resolved, excluded, conflicts := resolveCandidates(candidates, overrides)
	return map[string]any{
		"generation": generation,
		"resolved":   resolved,
		"excluded":   excluded,
		"conflicts":  conflicts,
	}, nil
}

var tierRank = map[string]int{"built-in": 4, "owner": 3, "workspace": 2, "repository": 1}

func resolveCandidates(candidates []candidateLike, overrides map[string]string) (resolved, excluded, conflicts []map[string]any) {
	type cand = candidateLike
	resolved = make([]map[string]any, 0)
	excluded = make([]map[string]any, 0)
	conflicts = make([]map[string]any, 0)
	usable := make([]cand, 0, len(candidates))
	for _, c := range candidates {
		if c.State == "disabled" || c.State == "archived" {
			excluded = append(excluded, map[string]any{"name": c.Name, "tier": c.Tier, "reason": c.State})
			continue
		}
		usable = append(usable, c)
	}
	byName := map[string][]cand{}
	names := make([]string, 0)
	for _, c := range usable {
		if _, ok := byName[c.Name]; !ok {
			names = append(names, c.Name)
		}
		byName[c.Name] = append(byName[c.Name], c)
	}
	sort.Strings(names)
	for _, name := range names {
		list := byName[name]
		pinned := false
		if override, ok := overrides[name]; ok {
			for _, c := range list {
				if c.RevisionID == override {
					resolved = append(resolved, map[string]any{
						"name": name, "tier": c.Tier, "skillSourceId": c.SourceID, "revisionId": c.RevisionID,
						"contentSha256": c.ContentSHA256, "pinned": true,
					})
					pinned = true
					break
				}
			}
		}
		if pinned {
			continue
		}
		sort.Slice(list, func(i, j int) bool {
			di := tierRank[list[j].Tier] - tierRank[list[i].Tier]
			if di != 0 {
				return di > 0
			}
			return list[i].RevisionID < list[j].RevisionID
		})
		winner := list[0]
		same := make([]cand, 0)
		digests := map[string]struct{}{}
		for _, c := range list {
			if c.Tier == winner.Tier {
				same = append(same, c)
				digests[c.ContentSHA256] = struct{}{}
			}
		}
		if len(digests) > 1 {
			cands := make([]map[string]any, 0, len(same))
			for _, c := range same {
				cands = append(cands, map[string]any{"tier": c.Tier, "revisionId": c.RevisionID})
			}
			conflicts = append(conflicts, map[string]any{"name": name, "candidates": cands, "candidateCount": len(cands)})
			continue
		}
		resolved = append(resolved, map[string]any{
			"name": name, "tier": winner.Tier, "skillSourceId": winner.SourceID, "revisionId": winner.RevisionID,
			"contentSha256": winner.ContentSHA256, "pinned": false,
		})
	}
	sort.Slice(excluded, func(i, j int) bool {
		ai, _ := excluded[i]["name"].(string)
		aj, _ := excluded[j]["name"].(string)
		return ai < aj
	})
	return resolved, excluded, conflicts
}

type candidateLike struct {
	Name, Tier, SourceID, RevisionID, ContentSHA256, State string
}

func (s *Store) StartImport(ownerID, kind, ref string, now int64) (ImportJob, error) {
	if _, ok := allowedImportKinds[kind]; !ok {
		return ImportJob{}, fmt.Errorf("%w: unsupported sourceKind", ErrInvalid)
	}
	if ref == "" || len(ref) > 300 || strings.Contains(ref, "\x00") {
		return ImportJob{}, fmt.Errorf("%w: sourceRef is invalid", ErrInvalid)
	}
	id := protocol.NewOpaqueID(protocol.PrefixSkillImportJob)
	if _, err := s.db.Exec(`INSERT INTO skill_import_jobs
		(owner_id, id, source_kind, source_ref, state, progress_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'queued', '{}', ?, ?)`, ownerID, id, kind, ref, now, now); err != nil {
		return ImportJob{}, err
	}
	return s.GetImport(ownerID, id)
}

func (s *Store) GetImport(ownerID, id string) (ImportJob, error) {
	var job ImportJob
	var progress string
	var result, errCode, rev sql.NullString
	err := s.db.QueryRow(`SELECT id, source_kind, source_ref, state, progress_json, result_json, error_code, skill_revision_id, created_at, updated_at
		FROM skill_import_jobs WHERE owner_id = ? AND id = ?`, ownerID, id).
		Scan(&job.ID, &job.SourceKind, &job.SourceRef, &job.State, &progress, &result, &errCode, &rev, &job.CreatedAt, &job.UpdatedAt)
	if err == sql.ErrNoRows {
		return ImportJob{}, ErrNotFound
	}
	if err != nil {
		return ImportJob{}, err
	}
	_ = json.Unmarshal([]byte(progress), &job.Progress)
	if job.Progress == nil {
		job.Progress = map[string]any{}
	}
	if result.Valid {
		var parsed any
		if json.Unmarshal([]byte(result.String), &parsed) == nil {
			job.Result = parsed
		} else {
			job.Result = result.String
		}
	}
	if errCode.Valid {
		job.ErrorCode = errCode.String
	}
	if rev.Valid {
		job.SkillRevisionID = rev.String
	}
	return job, nil
}

func (s *Store) CancelImport(ownerID, id string, now int64) (ImportJob, error) {
	job, err := s.GetImport(ownerID, id)
	if err != nil {
		return ImportJob{}, err
	}
	if job.State != "queued" && job.State != "running" {
		return ImportJob{}, ErrConflict
	}
	if _, err := s.db.Exec(`UPDATE skill_import_jobs SET state = 'cancelled', updated_at = ? WHERE owner_id = ? AND id = ?`, now, ownerID, id); err != nil {
		return ImportJob{}, err
	}
	return s.GetImport(ownerID, id)
}

// Now is unix-ms for tests.
func Now() int64 { return time.Now().UnixMilli() }
