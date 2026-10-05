package knowledge

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
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
	itemIDRe    = regexp.MustCompile(`^kn_[A-Za-z0-9_-]{10,80}$`)
	projectIDRe = regexp.MustCompile(`^prj_[A-Za-z0-9_-]{20,80}$`)
	tagRe       = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,50}$`)
)

var journalTypes = map[string]struct{}{
	"engineering-log":    {},
	"decision-record":    {},
	"session-reflection": {},
}

// Error is a public knowledge-store failure.
type Error struct {
	Code    protocol.ErrorCode
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(code protocol.ErrorCode, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Item is the public knowledge record.
type Item struct {
	ID            string
	PrincipalID   string
	Kind          string
	Scope         string
	ProjectID     string
	WorkspaceID   string
	Title         string
	Content       string
	ContentSHA256 string
	JournalType   string
	OccurredAt    int64
	Generation    int
	CreatedAt     int64
	UpdatedAt     int64
	ExpiresAt     int64
	Tags          []string
	Provenance    map[string]any
}

// PublicJSON is the Zod-compatible item object.
func (i Item) PublicJSON() map[string]any {
	out := map[string]any{
		"id":            i.ID,
		"principalId":   i.PrincipalID,
		"kind":          i.Kind,
		"scope":         i.Scope,
		"title":         i.Title,
		"content":       i.Content,
		"contentSha256": i.ContentSHA256,
		"generation":    i.Generation,
		"createdAt":     i.CreatedAt,
		"updatedAt":     i.UpdatedAt,
		"tags":          i.Tags,
		"provenance":    i.Provenance,
	}
	if i.ProjectID != "" {
		out["projectId"] = i.ProjectID
	} else {
		out["projectId"] = nil
	}
	if i.WorkspaceID != "" {
		out["workspaceId"] = i.WorkspaceID
	} else {
		out["workspaceId"] = nil
	}
	if i.JournalType != "" {
		out["journalType"] = i.JournalType
	} else {
		out["journalType"] = nil
	}
	if i.OccurredAt > 0 {
		out["occurredAt"] = i.OccurredAt
	} else {
		out["occurredAt"] = nil
	}
	if i.ExpiresAt > 0 {
		out["expiresAt"] = i.ExpiresAt
	} else {
		out["expiresAt"] = nil
	}
	out["deletedAt"] = nil
	return out
}

// Store keeps knowledge items in SQLite. FTS/embeddings stay unwired in this slice.
type Store struct {
	db *sql.DB
}

// Open creates the knowledge schema.
func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("knowledge store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS knowledge_items (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('memory','journal')),
  scope TEXT NOT NULL CHECK (scope IN ('owner','project','workspace')),
  project_id TEXT,
  workspace_id TEXT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  journal_type TEXT CHECK (journal_type IN ('engineering-log','decision-record','session-reflection') OR journal_type IS NULL),
  occurred_at INTEGER,
  generation INTEGER NOT NULL CHECK (generation > 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER,
  deleted_at INTEGER,
  provenance_json TEXT NOT NULL,
  CHECK (
    (scope='owner' AND project_id IS NULL AND workspace_id IS NULL) OR
    (scope='project' AND project_id IS NOT NULL AND workspace_id IS NULL) OR
    (scope='workspace' AND workspace_id IS NOT NULL)
  ),
  CHECK (
    (kind='journal' AND journal_type IS NOT NULL AND occurred_at IS NOT NULL) OR
    (kind='memory' AND journal_type IS NULL)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS knowledge_items_owner_mem_active ON knowledge_items(principal_id, title) WHERE deleted_at IS NULL AND kind='memory' AND scope='owner';
CREATE UNIQUE INDEX IF NOT EXISTS knowledge_items_project_mem_active ON knowledge_items(principal_id, project_id, title) WHERE deleted_at IS NULL AND kind='memory' AND scope='project';
CREATE UNIQUE INDEX IF NOT EXISTS knowledge_items_workspace_mem_active ON knowledge_items(principal_id, workspace_id, title) WHERE deleted_at IS NULL AND kind='memory' AND scope='workspace';
CREATE TABLE IF NOT EXISTS knowledge_tags (
  principal_id TEXT NOT NULL,
  item_id TEXT NOT NULL REFERENCES knowledge_items(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  PRIMARY KEY(principal_id, item_id, tag)
);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func newItemID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		panic("knowledge: crypto/rand unavailable")
	}
	return "kn_" + hex.EncodeToString(buf)
}

func normalizeTags(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	seen := map[string]struct{}{}
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if !tagRe.MatchString(tag) {
			return nil, fail(protocol.ErrorInvalidInput, "invalid knowledge tag")
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	if len(out) > 16 {
		return nil, fail(protocol.ErrorInvalidInput, "too many knowledge tags")
	}
	return out, nil
}

type CreateParams struct {
	PrincipalID        string
	Kind               string
	Scope              string
	ProjectID          string
	WorkspaceID        string
	Title              string
	Content            string
	JournalType        string
	OccurredAt         int64
	Tags               []string
	RetentionSeconds   int
	ExpectedGeneration int
}

type UpdateParams struct {
	PrincipalID        string
	ID                 string
	Title              *string
	Content            *string
	JournalType        *string
	OccurredAt         *int64
	Tags               *[]string
	RetentionSeconds   *int
	ExpectedGeneration int
}

type ListParams struct {
	PrincipalID string
	Kind        string
	Scope       string
	ProjectID   string
	WorkspaceID string
	JournalType string
	Tags        []string
	TagMatch    string
	Query       string
	Kinds       []string
	Limit       int
	Cursor      string
}

func (s *Store) Create(p CreateParams) (Item, error) {
	if p.ExpectedGeneration != 0 {
		return Item{}, fail(protocol.ErrorInvalidInput, "expectedGeneration must be 0 for item creation")
	}
	if p.Kind == "" {
		p.Kind = "memory"
	}
	if p.Kind != "memory" && p.Kind != "journal" {
		return Item{}, fail(protocol.ErrorInvalidInput, "invalid knowledge kind")
	}
	if p.Scope == "" {
		p.Scope = "workspace"
	}
	if p.Scope != "owner" && p.Scope != "project" && p.Scope != "workspace" {
		return Item{}, fail(protocol.ErrorInvalidInput, "invalid knowledge scope")
	}
	title := strings.TrimSpace(p.Title)
	if title == "" || len(title) > 120 {
		return Item{}, fail(protocol.ErrorInvalidInput, "invalid knowledge title")
	}
	if len(p.Content) > 262_144 {
		return Item{}, fail(protocol.ErrorInvalidInput, "knowledge content exceeds 262144 bytes")
	}
	tags, err := normalizeTags(p.Tags)
	if err != nil {
		return Item{}, err
	}
	switch p.Scope {
	case "owner":
		p.ProjectID = ""
		p.WorkspaceID = ""
	case "project":
		if !projectIDRe.MatchString(p.ProjectID) {
			return Item{}, fail(protocol.ErrorInvalidInput, "projectId is required for project-scoped knowledge")
		}
		p.WorkspaceID = ""
	case "workspace":
		if p.WorkspaceID == "" {
			return Item{}, fail(protocol.ErrorInvalidInput, "workspaceId is required for workspace-scoped knowledge")
		}
	}
	now := time.Now().UnixMilli()
	var journalType any
	var occurred any
	if p.Kind == "journal" {
		jt := p.JournalType
		if jt == "" {
			jt = "engineering-log"
		}
		if _, ok := journalTypes[jt]; !ok {
			return Item{}, fail(protocol.ErrorInvalidInput, "invalid journalType")
		}
		journalType = jt
		oc := p.OccurredAt
		if oc <= 0 {
			oc = now
		}
		occurred = oc
	} else if p.JournalType != "" {
		return Item{}, fail(protocol.ErrorInvalidInput, "memory item cannot have journalType")
	}
	var expires any
	if p.RetentionSeconds > 0 {
		expires = now + int64(p.RetentionSeconds)*1000
	}
	sum := sha256.Sum256([]byte(p.Content))
	sha := hex.EncodeToString(sum[:])
	id := newItemID()
	source := "owner"
	if p.Scope == "workspace" {
		source = "workspace"
	} else if p.Scope == "project" {
		source = "repository"
	}
	prov := map[string]any{
		"source": source, "trust": "owner-controlled", "mutableBy": "owner",
		"contentSha256": sha, "discoveredAt": time.UnixMilli(now).UTC().Format(time.RFC3339Nano),
	}
	raw, _ := json.Marshal(prov)
	tx, err := s.db.Begin()
	if err != nil {
		return Item{}, fail(protocol.ErrorInternal, err.Error())
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO knowledge_items (id, principal_id, kind, scope, project_id, workspace_id, title, content, content_sha256, journal_type, occurred_at, generation, created_at, updated_at, expires_at, deleted_at, provenance_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL, ?)`,
		id, p.PrincipalID, p.Kind, p.Scope, nullString(p.ProjectID), nullString(p.WorkspaceID), title, p.Content, sha, journalType, occurred, now, now, expires, string(raw)); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Item{}, fail(protocol.ErrorConflict, "knowledge item already exists with this title in the given scope")
		}
		return Item{}, fail(protocol.ErrorInternal, err.Error())
	}
	for _, tag := range tags {
		if _, err := tx.Exec(`INSERT INTO knowledge_tags (principal_id, item_id, tag) VALUES (?, ?, ?)`, p.PrincipalID, id, tag); err != nil {
			return Item{}, fail(protocol.ErrorInternal, err.Error())
		}
	}
	if err := tx.Commit(); err != nil {
		return Item{}, fail(protocol.ErrorInternal, err.Error())
	}
	item := Item{
		ID: id, PrincipalID: p.PrincipalID, Kind: p.Kind, Scope: p.Scope, ProjectID: p.ProjectID,
		WorkspaceID: p.WorkspaceID, Title: title, Content: p.Content, ContentSHA256: sha,
		Tags: tags, Generation: 1, CreatedAt: now, UpdatedAt: now, Provenance: prov,
	}
	if jt, ok := journalType.(string); ok {
		item.JournalType = jt
	}
	if oc, ok := occurred.(int64); ok {
		item.OccurredAt = oc
	}
	if exp, ok := expires.(int64); ok {
		item.ExpiresAt = exp
	}
	return item, nil
}

func (s *Store) Read(principalID, id string) (Item, error) {
	if !itemIDRe.MatchString(id) {
		return Item{}, fail(protocol.ErrorInvalidInput, "invalid knowledge item identifier")
	}
	now := time.Now().UnixMilli()
	item, err := scanItem(s.db.QueryRow(`SELECT id, principal_id, kind, scope, project_id, workspace_id, title, content, content_sha256, journal_type, occurred_at, generation, created_at, updated_at, expires_at, provenance_json FROM knowledge_items WHERE id = ? AND principal_id = ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, id, principalID, now))
	if err == sql.ErrNoRows {
		return Item{}, fail(protocol.ErrorNotFound, "knowledge item not found")
	}
	if err != nil {
		return Item{}, fail(protocol.ErrorInternal, err.Error())
	}
	tags, err := s.tagsFor(item.ID)
	if err != nil {
		return Item{}, err
	}
	item.Tags = tags
	return item, nil
}

func (s *Store) Update(p UpdateParams) (Item, error) {
	if p.ExpectedGeneration < 1 {
		return Item{}, fail(protocol.ErrorInvalidInput, "expectedGeneration is required")
	}
	item, err := s.Read(p.PrincipalID, p.ID)
	if err != nil {
		return Item{}, err
	}
	if item.Generation != p.ExpectedGeneration {
		return Item{}, fail(protocol.ErrorConflict, "knowledge item generation conflict")
	}
	if p.Title != nil {
		title := strings.TrimSpace(*p.Title)
		if title == "" || len(title) > 120 {
			return Item{}, fail(protocol.ErrorInvalidInput, "invalid knowledge title")
		}
		item.Title = title
	}
	if p.Content != nil {
		if len(*p.Content) > 262_144 {
			return Item{}, fail(protocol.ErrorInvalidInput, "knowledge content exceeds 262144 bytes")
		}
		item.Content = *p.Content
	}
	if p.Tags != nil {
		tags, err := normalizeTags(*p.Tags)
		if err != nil {
			return Item{}, err
		}
		item.Tags = tags
	}
	if item.Kind == "journal" {
		if p.JournalType != nil {
			if _, ok := journalTypes[*p.JournalType]; !ok {
				return Item{}, fail(protocol.ErrorInvalidInput, "invalid journalType")
			}
			item.JournalType = *p.JournalType
		}
		if p.OccurredAt != nil {
			item.OccurredAt = *p.OccurredAt
		}
	}
	now := time.Now().UnixMilli()
	if p.RetentionSeconds != nil {
		if *p.RetentionSeconds > 0 {
			item.ExpiresAt = now + int64(*p.RetentionSeconds)*1000
		} else {
			item.ExpiresAt = 0
		}
	}
	sum := sha256.Sum256([]byte(item.Content))
	item.ContentSHA256 = hex.EncodeToString(sum[:])
	if item.Provenance == nil {
		item.Provenance = map[string]any{}
	}
	item.Provenance["contentSha256"] = item.ContentSHA256
	item.Provenance["discoveredAt"] = time.UnixMilli(now).UTC().Format(time.RFC3339Nano)
	raw, _ := json.Marshal(item.Provenance)
	next := item.Generation + 1
	tx, err := s.db.Begin()
	if err != nil {
		return Item{}, fail(protocol.ErrorInternal, err.Error())
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE knowledge_items SET title = ?, content = ?, content_sha256 = ?, journal_type = ?, occurred_at = ?, generation = ?, updated_at = ?, expires_at = ?, provenance_json = ? WHERE id = ? AND generation = ? AND deleted_at IS NULL`,
		item.Title, item.Content, item.ContentSHA256, nullString(item.JournalType), nullInt(item.OccurredAt), next, now, nullInt(item.ExpiresAt), string(raw), item.ID, item.Generation)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Item{}, fail(protocol.ErrorConflict, "knowledge item already exists with this title in the given scope")
		}
		return Item{}, fail(protocol.ErrorInternal, err.Error())
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return Item{}, fail(protocol.ErrorConflict, "knowledge item generation conflict")
	}
	if p.Tags != nil {
		if _, err := tx.Exec(`DELETE FROM knowledge_tags WHERE item_id = ?`, item.ID); err != nil {
			return Item{}, fail(protocol.ErrorInternal, err.Error())
		}
		for _, tag := range item.Tags {
			if _, err := tx.Exec(`INSERT INTO knowledge_tags (principal_id, item_id, tag) VALUES (?, ?, ?)`, p.PrincipalID, item.ID, tag); err != nil {
				return Item{}, fail(protocol.ErrorInternal, err.Error())
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return Item{}, fail(protocol.ErrorInternal, err.Error())
	}
	item.Generation = next
	item.UpdatedAt = now
	return item, nil
}

func (s *Store) Delete(principalID, id string, expectedGeneration int) error {
	if expectedGeneration < 1 {
		return fail(protocol.ErrorInvalidInput, "expectedGeneration is required")
	}
	item, err := s.Read(principalID, id)
	if err != nil {
		return err
	}
	if item.Generation != expectedGeneration {
		return fail(protocol.ErrorConflict, "knowledge item generation conflict")
	}
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`UPDATE knowledge_items SET deleted_at = ? WHERE id = ? AND generation = ? AND deleted_at IS NULL`, now, id, expectedGeneration)
	if err != nil {
		return fail(protocol.ErrorInternal, err.Error())
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fail(protocol.ErrorConflict, "knowledge item generation conflict")
	}
	return nil
}

func (s *Store) List(p ListParams) ([]Item, string, error) {
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > 100 {
		return nil, "", fail(protocol.ErrorInvalidInput, "limit must be between 1 and 100")
	}
	return s.query(p, p.Limit)
}

func (s *Store) Search(p ListParams) ([]Item, string, error) {
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

func (s *Store) query(p ListParams, limit int) ([]Item, string, error) {
	offset := 0
	if p.Cursor != "" {
		n, err := strconv.Atoi(p.Cursor)
		if err != nil || n < 0 {
			return nil, "", fail(protocol.ErrorInvalidInput, "invalid knowledge cursor")
		}
		offset = n
	}
	now := time.Now().UnixMilli()
	q := `SELECT id, principal_id, kind, scope, project_id, workspace_id, title, content, content_sha256, journal_type, occurred_at, generation, created_at, updated_at, expires_at, provenance_json FROM knowledge_items WHERE principal_id = ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`
	args := []any{p.PrincipalID, now}
	if p.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, p.Kind)
	}
	if len(p.Kinds) > 0 {
		placeholders := strings.Repeat("?,", len(p.Kinds))
		q += ` AND kind IN (` + placeholders[:len(placeholders)-1] + `)`
		for _, k := range p.Kinds {
			args = append(args, k)
		}
	}
	if p.Scope != "" {
		q += ` AND scope = ?`
		args = append(args, p.Scope)
		if p.Scope == "project" && p.ProjectID != "" {
			q += ` AND project_id = ?`
			args = append(args, p.ProjectID)
		} else if p.Scope == "workspace" && p.WorkspaceID != "" {
			q += ` AND workspace_id = ?`
			args = append(args, p.WorkspaceID)
		}
	} else if p.WorkspaceID != "" || p.ProjectID != "" {
		q += ` AND (scope = 'owner'`
		if p.ProjectID != "" {
			q += ` OR (scope = 'project' AND project_id = ?)`
			args = append(args, p.ProjectID)
		}
		if p.WorkspaceID != "" {
			q += ` OR (scope = 'workspace' AND workspace_id = ?)`
			args = append(args, p.WorkspaceID)
		}
		q += `)`
	}
	if p.JournalType != "" {
		q += ` AND journal_type = ?`
		args = append(args, p.JournalType)
	}
	tags, err := normalizeTags(p.Tags)
	if err != nil {
		return nil, "", err
	}
	if len(tags) > 0 {
		placeholders := strings.Repeat("?,", len(tags))
		placeholders = placeholders[:len(placeholders)-1]
		if p.TagMatch == "any" {
			q += ` AND id IN (SELECT item_id FROM knowledge_tags WHERE tag IN (` + placeholders + `))`
			for _, tag := range tags {
				args = append(args, tag)
			}
		} else {
			q += ` AND id IN (SELECT item_id FROM knowledge_tags WHERE tag IN (` + placeholders + `) GROUP BY item_id HAVING COUNT(DISTINCT tag) = ?)`
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
	var matched []Item
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, "", fail(protocol.ErrorInternal, err.Error())
		}
		tags, err := s.tagsFor(item.ID)
		if err != nil {
			return nil, "", err
		}
		item.Tags = tags
		if len(tokens) > 0 {
			haystack := strings.ToLower(item.Title + "\n" + item.Content + "\n" + strings.Join(item.Tags, " "))
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
		matched = append(matched, item)
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

func (s *Store) tagsFor(id string) ([]string, error) {
	rows, err := s.db.Query(`SELECT tag FROM knowledge_tags WHERE item_id = ? ORDER BY tag`, id)
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

func scanItem(row rowScanner) (Item, error) {
	var item Item
	var project, ws, journal, prov sql.NullString
	var occurred, expires sql.NullInt64
	if err := row.Scan(&item.ID, &item.PrincipalID, &item.Kind, &item.Scope, &project, &ws, &item.Title, &item.Content, &item.ContentSHA256, &journal, &occurred, &item.Generation, &item.CreatedAt, &item.UpdatedAt, &expires, &prov); err != nil {
		return Item{}, err
	}
	item.ProjectID = project.String
	item.WorkspaceID = ws.String
	item.JournalType = journal.String
	item.OccurredAt = occurred.Int64
	item.ExpiresAt = expires.Int64
	if prov.String != "" {
		_ = json.Unmarshal([]byte(prov.String), &item.Provenance)
	}
	if item.Tags == nil {
		item.Tags = []string{}
	}
	return item, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}
