package memories

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

var (
	memoryNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)
	memoryIDRe   = regexp.MustCompile(`^mem_[A-Za-z0-9_-]{10,80}$`)
	tagRe        = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,50}$`)
)

const defaultRetentionMs = int64(90 * 86_400_000)

// Error is a public memory-store failure.
type Error struct {
	Code    protocol.ErrorCode
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(code protocol.ErrorCode, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Record is the public memory note.
type Record struct {
	ID            string
	PrincipalID   string
	Scope         string
	RepositoryKey string
	WorkspaceID   string
	Name          string
	Content       string
	ContentSHA256 string
	Tags          []string
	Generation    int
	CreatedAt     int64
	UpdatedAt     int64
	ExpiresAt     int64
	Provenance    map[string]any
}

// PublicJSON is the Zod-compatible memory object.
func (r Record) PublicJSON() map[string]any {
	out := map[string]any{
		"id":            r.ID,
		"name":          r.Name,
		"scope":         r.Scope,
		"content":       r.Content,
		"contentSha256": r.ContentSHA256,
		"tags":          r.Tags,
		"generation":    r.Generation,
		"createdAt":     r.CreatedAt,
		"updatedAt":     r.UpdatedAt,
		"expiresAt":     r.ExpiresAt,
		"provenance":    r.Provenance,
	}
	if r.WorkspaceID != "" {
		out["workspaceId"] = r.WorkspaceID
	}
	return out
}

// ListJSON omits content.
func (r Record) ListJSON() map[string]any {
	out := map[string]any{
		"id":         r.ID,
		"name":       r.Name,
		"scope":      r.Scope,
		"tags":       r.Tags,
		"generation": r.Generation,
		"provenance": r.Provenance,
	}
	if r.WorkspaceID != "" {
		out["workspaceId"] = r.WorkspaceID
	}
	return out
}

// Store keeps memory notes in SQLite.
type Store struct {
	db *sql.DB
}

// Open creates the memories schema.
func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("memory store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS memories (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('owner','repository','workspace')),
  repository_key TEXT,
  workspace_id TEXT,
  name TEXT NOT NULL,
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  deleted_at INTEGER,
  provenance_json TEXT NOT NULL,
  CHECK (
    (scope='owner' AND repository_key IS NULL AND workspace_id IS NULL) OR
    (scope='repository' AND repository_key IS NOT NULL AND workspace_id IS NULL) OR
    (scope='workspace' AND workspace_id IS NOT NULL)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS memories_owner_active ON memories(principal_id, name) WHERE deleted_at IS NULL AND scope='owner';
CREATE UNIQUE INDEX IF NOT EXISTS memories_repo_active ON memories(principal_id, repository_key, name) WHERE deleted_at IS NULL AND scope='repository';
CREATE UNIQUE INDEX IF NOT EXISTS memories_ws_active ON memories(principal_id, workspace_id, name) WHERE deleted_at IS NULL AND scope='workspace';
CREATE INDEX IF NOT EXISTS memories_expiry ON memories(expires_at, deleted_at);
CREATE TABLE IF NOT EXISTS memory_tags (
  principal_id TEXT NOT NULL,
  memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  PRIMARY KEY(principal_id, memory_id, tag)
);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

type WriteParams struct {
	PrincipalID        string
	Scope              string
	RepositoryKey      string
	WorkspaceID        string
	Name               string
	Content            string
	Tags               []string
	RetentionSeconds   int
	ExpectedGeneration int
}

type Lookup struct {
	PrincipalID   string
	ID            string
	Name          string
	Scope         string
	RepositoryKey string
	WorkspaceID   string
}

type ListParams struct {
	PrincipalID   string
	Scope         string
	RepositoryKey string
	WorkspaceID   string
	Tags          []string
	TagMatch      string
	Query         string
	Limit         int
	Cursor        string
}

func newMemoryID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("memories: crypto/rand unavailable")
	}
	return "mem_" + base64.RawURLEncoding.EncodeToString(buf)
}

func validScope(scope string) bool {
	return scope == "owner" || scope == "repository" || scope == "workspace"
}

func normalizeTags(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	seen := map[string]struct{}{}
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if len(tag) > 50 || !tagRe.MatchString(tag) {
			return nil, fail(protocol.ErrorInvalidInput, "invalid memory tag")
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	if len(out) > 16 {
		return nil, fail(protocol.ErrorInvalidInput, "too many memory tags")
	}
	return out, nil
}

func provenance(scope, sha string, now int64) map[string]any {
	source := scope
	trust := "untrusted-executor"
	mutable := "workspace-process"
	switch scope {
	case "owner":
		trust = "owner-controlled"
		mutable = "owner"
	case "repository":
		mutable = "repository-commit"
	}
	return map[string]any{
		"source":        source,
		"trust":         trust,
		"mutableBy":     mutable,
		"contentSha256": sha,
		"discoveredAt":  time.UnixMilli(now).UTC().Format(time.RFC3339Nano),
	}
}

func (s *Store) Write(p WriteParams) (Record, error) {
	if !memoryNameRe.MatchString(p.Name) {
		return Record{}, fail(protocol.ErrorInvalidInput, "invalid memory name")
	}
	if p.Scope == "" {
		p.Scope = "workspace"
	}
	if !validScope(p.Scope) {
		return Record{}, fail(protocol.ErrorInvalidInput, "invalid memory scope")
	}
	if len(p.Content) > 262_144 {
		return Record{}, fail(protocol.ErrorInvalidInput, "memory content exceeds 262144 bytes")
	}
	tags, err := normalizeTags(p.Tags)
	if err != nil {
		return Record{}, err
	}
	switch p.Scope {
	case "owner":
		p.RepositoryKey = ""
		p.WorkspaceID = ""
	case "repository":
		if p.RepositoryKey == "" {
			return Record{}, fail(protocol.ErrorInvalidInput, "repositoryKey is required for repository-scoped memories")
		}
		p.WorkspaceID = ""
	case "workspace":
		if p.WorkspaceID == "" {
			return Record{}, fail(protocol.ErrorInvalidInput, "workspaceId is required for workspace-scoped memories")
		}
	}
	if p.ExpectedGeneration == 0 {
		return s.create(p, tags)
	}
	return s.update(p, tags)
}

func (s *Store) create(p WriteParams, tags []string) (Record, error) {
	now := time.Now().UnixMilli()
	ttl := defaultRetentionMs
	if p.RetentionSeconds > 0 {
		ttl = int64(p.RetentionSeconds) * 1000
	}
	expires := now + ttl
	sum := sha256.Sum256([]byte(p.Content))
	sha := hex.EncodeToString(sum[:])
	id := newMemoryID()
	prov := provenance(p.Scope, sha, now)
	raw, _ := json.Marshal(prov)
	tx, err := s.db.Begin()
	if err != nil {
		return Record{}, fail(protocol.ErrorInternal, err.Error())
	}
	defer func() { _ = tx.Rollback() }()
	var existing string
	switch p.Scope {
	case "owner":
		err = tx.QueryRow(`SELECT id FROM memories WHERE principal_id = ? AND name = ? AND scope = 'owner' AND deleted_at IS NULL AND expires_at > ?`, p.PrincipalID, p.Name, now).Scan(&existing)
		if err == nil {
			return Record{}, fail(protocol.ErrorConflict, "memory note already exists with this name in the given scope")
		}
		if err != sql.ErrNoRows {
			return Record{}, fail(protocol.ErrorInternal, err.Error())
		}
		if _, err := tx.Exec(`DELETE FROM memories WHERE principal_id = ? AND name = ? AND scope = 'owner' AND (expires_at <= ? OR deleted_at IS NOT NULL)`, p.PrincipalID, p.Name, now); err != nil {
			return Record{}, fail(protocol.ErrorInternal, err.Error())
		}
	case "repository":
		err = tx.QueryRow(`SELECT id FROM memories WHERE principal_id = ? AND name = ? AND repository_key = ? AND scope = 'repository' AND deleted_at IS NULL AND expires_at > ?`, p.PrincipalID, p.Name, p.RepositoryKey, now).Scan(&existing)
		if err == nil {
			return Record{}, fail(protocol.ErrorConflict, "memory note already exists with this name in the given scope")
		}
		if err != sql.ErrNoRows {
			return Record{}, fail(protocol.ErrorInternal, err.Error())
		}
		if _, err := tx.Exec(`DELETE FROM memories WHERE principal_id = ? AND name = ? AND repository_key = ? AND scope = 'repository' AND (expires_at <= ? OR deleted_at IS NOT NULL)`, p.PrincipalID, p.Name, p.RepositoryKey, now); err != nil {
			return Record{}, fail(protocol.ErrorInternal, err.Error())
		}
	default:
		err = tx.QueryRow(`SELECT id FROM memories WHERE principal_id = ? AND name = ? AND workspace_id = ? AND scope = 'workspace' AND deleted_at IS NULL AND expires_at > ?`, p.PrincipalID, p.Name, p.WorkspaceID, now).Scan(&existing)
		if err == nil {
			return Record{}, fail(protocol.ErrorConflict, "memory note already exists with this name in the given scope")
		}
		if err != sql.ErrNoRows {
			return Record{}, fail(protocol.ErrorInternal, err.Error())
		}
		if _, err := tx.Exec(`DELETE FROM memories WHERE principal_id = ? AND name = ? AND workspace_id = ? AND scope = 'workspace' AND (expires_at <= ? OR deleted_at IS NOT NULL)`, p.PrincipalID, p.Name, p.WorkspaceID, now); err != nil {
			return Record{}, fail(protocol.ErrorInternal, err.Error())
		}
	}
	if _, err := tx.Exec(`INSERT INTO memories (id, principal_id, scope, repository_key, workspace_id, name, content, content_sha256, generation, created_at, updated_at, expires_at, deleted_at, provenance_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL, ?)`,
		id, p.PrincipalID, p.Scope, nullString(p.RepositoryKey), nullString(p.WorkspaceID), p.Name, p.Content, sha, now, now, expires, string(raw)); err != nil {
		return Record{}, fail(protocol.ErrorInternal, err.Error())
	}
	for _, tag := range tags {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO memory_tags (principal_id, memory_id, tag) VALUES (?, ?, ?)`, p.PrincipalID, id, tag); err != nil {
			return Record{}, fail(protocol.ErrorInternal, err.Error())
		}
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fail(protocol.ErrorInternal, err.Error())
	}
	return Record{
		ID: id, PrincipalID: p.PrincipalID, Scope: p.Scope, RepositoryKey: p.RepositoryKey,
		WorkspaceID: p.WorkspaceID, Name: p.Name, Content: p.Content, ContentSHA256: sha,
		Tags: tags, Generation: 1, CreatedAt: now, UpdatedAt: now, ExpiresAt: expires, Provenance: prov,
	}, nil
}

func (s *Store) update(p WriteParams, tags []string) (Record, error) {
	now := time.Now().UnixMilli()
	ttl := defaultRetentionMs
	if p.RetentionSeconds > 0 {
		ttl = int64(p.RetentionSeconds) * 1000
	}
	expires := now + ttl
	sum := sha256.Sum256([]byte(p.Content))
	sha := hex.EncodeToString(sum[:])
	tx, err := s.db.Begin()
	if err != nil {
		return Record{}, fail(protocol.ErrorInternal, err.Error())
	}
	defer func() { _ = tx.Rollback() }()
	row, err := s.lookupTx(tx, Lookup{PrincipalID: p.PrincipalID, Name: p.Name, Scope: p.Scope, RepositoryKey: p.RepositoryKey, WorkspaceID: p.WorkspaceID}, now)
	if err != nil {
		return Record{}, err
	}
	if row.Generation != p.ExpectedGeneration {
		return Record{}, fail(protocol.ErrorConflict, fmt.Sprintf("memory generation conflict: expected %d, current is %d", p.ExpectedGeneration, row.Generation))
	}
	prov := row.Provenance
	if prov == nil {
		prov = map[string]any{}
	}
	prov["contentSha256"] = sha
	prov["discoveredAt"] = time.UnixMilli(now).UTC().Format(time.RFC3339Nano)
	raw, _ := json.Marshal(prov)
	next := row.Generation + 1
	res, err := tx.Exec(`UPDATE memories SET content = ?, content_sha256 = ?, generation = ?, updated_at = ?, expires_at = ?, provenance_json = ? WHERE id = ? AND generation = ?`,
		p.Content, sha, next, now, expires, string(raw), row.ID, row.Generation)
	if err != nil {
		return Record{}, fail(protocol.ErrorInternal, err.Error())
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return Record{}, fail(protocol.ErrorConflict, "memory generation conflict")
	}
	if _, err := tx.Exec(`DELETE FROM memory_tags WHERE memory_id = ?`, row.ID); err != nil {
		return Record{}, fail(protocol.ErrorInternal, err.Error())
	}
	for _, tag := range tags {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO memory_tags (principal_id, memory_id, tag) VALUES (?, ?, ?)`, p.PrincipalID, row.ID, tag); err != nil {
			return Record{}, fail(protocol.ErrorInternal, err.Error())
		}
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fail(protocol.ErrorInternal, err.Error())
	}
	row.Content = p.Content
	row.ContentSHA256 = sha
	row.Tags = tags
	row.Generation = next
	row.UpdatedAt = now
	row.ExpiresAt = expires
	row.Provenance = prov
	return row, nil
}

func (s *Store) Read(p Lookup) (Record, error) {
	if p.ID == "" && p.Name == "" {
		return Record{}, fail(protocol.ErrorInvalidInput, "name or memoryId is required")
	}
	if p.ID != "" && !memoryIDRe.MatchString(p.ID) {
		return Record{}, fail(protocol.ErrorInvalidInput, "invalid memoryId")
	}
	if p.Name != "" && !memoryNameRe.MatchString(p.Name) {
		return Record{}, fail(protocol.ErrorInvalidInput, "invalid memory name")
	}
	if p.Scope != "" && !validScope(p.Scope) {
		return Record{}, fail(protocol.ErrorInvalidInput, "invalid memory scope")
	}
	now := time.Now().UnixMilli()
	row, err := s.lookupTx(s.db, p, now)
	if err != nil {
		return Record{}, err
	}
	return row, nil
}

func (s *Store) Delete(p Lookup, expectedGeneration int) error {
	if p.ID == "" && p.Name == "" {
		return fail(protocol.ErrorInvalidInput, "memoryId or name is required")
	}
	if expectedGeneration < 1 {
		expectedGeneration = 1
	}
	now := time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return fail(protocol.ErrorInternal, err.Error())
	}
	defer func() { _ = tx.Rollback() }()
	row, err := s.lookupTx(tx, p, 0)
	if err != nil {
		return err
	}
	if row.Generation != expectedGeneration {
		return fail(protocol.ErrorConflict, fmt.Sprintf("memory generation conflict: expected %d, current is %d", expectedGeneration, row.Generation))
	}
	if _, err := tx.Exec(`UPDATE memories SET deleted_at = ? WHERE id = ?`, now, row.ID); err != nil {
		return fail(protocol.ErrorInternal, err.Error())
	}
	return tx.Commit()
}

func (s *Store) List(p ListParams) ([]Record, string, error) {
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > 100 {
		return nil, "", fail(protocol.ErrorInvalidInput, "limit must be between 1 and 100")
	}
	return s.query(p, p.Limit)
}

func (s *Store) Search(p ListParams) ([]Record, string, error) {
	if strings.TrimSpace(p.Query) == "" {
		return nil, "", fail(protocol.ErrorInvalidInput, "query is required")
	}
	if p.Limit <= 0 {
		p.Limit = 20
	}
	if p.Limit > 50 {
		return nil, "", fail(protocol.ErrorInvalidInput, "limit must be between 1 and 50")
	}
	return s.query(p, p.Limit)
}

func (s *Store) query(p ListParams, limit int) ([]Record, string, error) {
	if p.Scope != "" && !validScope(p.Scope) {
		return nil, "", fail(protocol.ErrorInvalidInput, "invalid memory scope")
	}
	offset := 0
	if p.Cursor != "" {
		n, err := strconv.Atoi(p.Cursor)
		if err != nil || n < 0 {
			return nil, "", fail(protocol.ErrorInvalidInput, "invalid memories cursor")
		}
		offset = n
	}
	now := time.Now().UnixMilli()
	q := `SELECT id, principal_id, scope, repository_key, workspace_id, name, content, content_sha256, generation, created_at, updated_at, expires_at, provenance_json FROM memories WHERE principal_id = ? AND deleted_at IS NULL AND expires_at > ?`
	args := []any{p.PrincipalID, now}
	if p.Scope != "" {
		q += ` AND scope = ?`
		args = append(args, p.Scope)
		if p.Scope == "repository" && p.RepositoryKey != "" {
			q += ` AND repository_key = ?`
			args = append(args, p.RepositoryKey)
		} else if p.Scope == "workspace" && p.WorkspaceID != "" {
			q += ` AND workspace_id = ?`
			args = append(args, p.WorkspaceID)
		}
	} else if p.RepositoryKey != "" || p.WorkspaceID != "" {
		q += ` AND (scope = 'owner'`
		if p.RepositoryKey != "" {
			q += ` OR (scope = 'repository' AND repository_key = ?)`
			args = append(args, p.RepositoryKey)
		}
		if p.WorkspaceID != "" {
			q += ` OR (scope = 'workspace' AND workspace_id = ?)`
			args = append(args, p.WorkspaceID)
		}
		q += `)`
	} else {
		q += ` AND scope = 'owner'`
	}
	tags, err := normalizeTags(p.Tags)
	if err != nil {
		return nil, "", err
	}
	if len(tags) > 0 {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = placeholders[:len(placeholders)-1]
		if p.TagMatch == "any" {
			q += ` AND id IN (SELECT memory_id FROM memory_tags WHERE tag IN (` + placeholders + `))`
			for _, tag := range tags {
				args = append(args, tag)
			}
		} else {
			q += ` AND id IN (SELECT memory_id FROM memory_tags WHERE tag IN (` + placeholders + `) GROUP BY memory_id HAVING COUNT(DISTINCT tag) = ?)`
			for _, tag := range tags {
				args = append(args, tag)
			}
			args = append(args, len(tags))
		}
	}
	q += ` ORDER BY updated_at DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, "", fail(protocol.ErrorInternal, err.Error())
	}
	defer rows.Close()
	tokens := strings.Fields(strings.ToLower(strings.TrimSpace(p.Query)))
	var matched []Record
	for rows.Next() {
		rec, err := scanMemory(rows)
		if err != nil {
			return nil, "", fail(protocol.ErrorInternal, err.Error())
		}
		tags, err := s.tagsFor(rec.ID)
		if err != nil {
			return nil, "", err
		}
		rec.Tags = tags
		if len(tokens) > 0 {
			haystack := strings.ToLower(rec.Name + "\n" + rec.Content)
			ok := true
			for _, tok := range tokens {
				if !strings.Contains(haystack, tok) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		matched = append(matched, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fail(protocol.ErrorInternal, err.Error())
	}
	if offset > len(matched) {
		offset = len(matched)
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	out := matched[offset:end]
	var next string
	if end < len(matched) {
		next = strconv.Itoa(end)
	}
	return out, next, nil
}

type querier interface {
	QueryRow(query string, args ...any) *sql.Row
}

func (s *Store) lookupTx(q querier, p Lookup, now int64) (Record, error) {
	sqlq := `SELECT id, principal_id, scope, repository_key, workspace_id, name, content, content_sha256, generation, created_at, updated_at, expires_at, provenance_json FROM memories WHERE principal_id = ? AND deleted_at IS NULL`
	args := []any{p.PrincipalID}
	if now > 0 {
		sqlq += ` AND expires_at > ?`
		args = append(args, now)
	}
	if p.ID != "" {
		sqlq += ` AND id = ?`
		args = append(args, p.ID)
	} else if p.Name != "" {
		sqlq += ` AND name = ?`
		args = append(args, p.Name)
	} else {
		return Record{}, fail(protocol.ErrorInvalidInput, "name or memoryId is required")
	}
	if p.Scope != "" {
		sqlq += ` AND scope = ?`
		args = append(args, p.Scope)
		if p.Scope == "repository" && p.RepositoryKey != "" {
			sqlq += ` AND repository_key = ?`
			args = append(args, p.RepositoryKey)
		} else if p.Scope == "workspace" && p.WorkspaceID != "" {
			sqlq += ` AND workspace_id = ?`
			args = append(args, p.WorkspaceID)
		}
	} else if p.RepositoryKey != "" || p.WorkspaceID != "" {
		sqlq += ` AND (scope = 'owner'`
		if p.RepositoryKey != "" {
			sqlq += ` OR (scope = 'repository' AND repository_key = ?)`
			args = append(args, p.RepositoryKey)
		}
		if p.WorkspaceID != "" {
			sqlq += ` OR (scope = 'workspace' AND workspace_id = ?)`
			args = append(args, p.WorkspaceID)
		}
		sqlq += `)`
	}
	sqlq += ` ORDER BY updated_at DESC LIMIT 1`
	rec, err := scanMemory(q.QueryRow(sqlq, args...))
	if err == sql.ErrNoRows {
		return Record{}, fail(protocol.ErrorNotFound, "memory note not found")
	}
	if err != nil {
		return Record{}, fail(protocol.ErrorInternal, err.Error())
	}
	tags, err := s.tagsFor(rec.ID)
	if err != nil {
		return Record{}, err
	}
	rec.Tags = tags
	return rec, nil
}

func (s *Store) tagsFor(id string) ([]string, error) {
	rows, err := s.db.Query(`SELECT tag FROM memory_tags WHERE memory_id = ? ORDER BY tag`, id)
	if err != nil {
		return nil, fail(protocol.ErrorInternal, err.Error())
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, fail(protocol.ErrorInternal, err.Error())
		}
		tags = append(tags, tag)
	}
	if tags == nil {
		tags = []string{}
	}
	return tags, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMemory(row rowScanner) (Record, error) {
	var rec Record
	var repo, ws, prov sql.NullString
	if err := row.Scan(&rec.ID, &rec.PrincipalID, &rec.Scope, &repo, &ws, &rec.Name, &rec.Content, &rec.ContentSHA256, &rec.Generation, &rec.CreatedAt, &rec.UpdatedAt, &rec.ExpiresAt, &prov); err != nil {
		return Record{}, err
	}
	rec.RepositoryKey = repo.String
	rec.WorkspaceID = ws.String
	if prov.String != "" {
		_ = json.Unmarshal([]byte(prov.String), &rec.Provenance)
	}
	if rec.Tags == nil {
		rec.Tags = []string{}
	}
	return rec, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
