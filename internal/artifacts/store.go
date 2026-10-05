package artifacts

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

var (
	logicalNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	artifactFile  = regexp.MustCompile(`^(art_[A-Za-z0-9_-]{32})\.snapshot$`)
	temporaryFile = regexp.MustCompile(`^\.tmp-art_[A-Za-z0-9_-]{32}-[a-f0-9]{16}$`)
	tombstoneFile = regexp.MustCompile(`^\.deleting-(art_[A-Za-z0-9_-]{32})-[1-9][0-9]*-[a-f0-9]{16}$`)
	relativeSafe  = regexp.MustCompile(`^objects/art_[A-Za-z0-9_-]{32}\.snapshot$`)
	cursorIDRe    = regexp.MustCompile(`^art_[A-Za-z0-9_-]{32}$`)
)

// Error is a public artifact-store failure.
type Error struct {
	Code    protocol.ErrorCode
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(code protocol.ErrorCode, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Metadata is the public artifact view. Payload bytes are never included.
type Metadata struct {
	ArtifactID    string
	LogicalName   string
	SHA256        string
	SizeBytes     int
	ProjectID     string
	EnvironmentID string
	WorkspaceID   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ExpiresAt     time.Time
	RetentionMs   int64
	Generation    int
	relativePath  string
}

// PublicJSON is the Zod-compatible metadata object.
func (m Metadata) PublicJSON() map[string]any {
	out := map[string]any{
		"artifactId":  m.ArtifactID,
		"logicalName": m.LogicalName,
		"sha256":      m.SHA256,
		"sizeBytes":   m.SizeBytes,
		"createdAt":   m.CreatedAt.UnixMilli(),
		"updatedAt":   m.UpdatedAt.UnixMilli(),
		"expiresAt":   m.ExpiresAt.UnixMilli(),
		"retentionMs": m.RetentionMs,
		"generation":  m.Generation,
	}
	if m.ProjectID != "" {
		out["projectId"] = m.ProjectID
	}
	if m.EnvironmentID != "" {
		out["environmentId"] = m.EnvironmentID
	}
	if m.WorkspaceID != "" {
		out["workspaceId"] = m.WorkspaceID
	}
	return out
}

// Options bound object size and retention.
type Options struct {
	Root               string
	MaxArtifactBytes   int
	MaxPrincipalBytes  int
	DefaultRetentionMs int64
	MaxRetentionMs     int64
}

func (o Options) withDefaults() Options {
	if o.MaxArtifactBytes <= 0 {
		o.MaxArtifactBytes = 1 << 20
	}
	if o.MaxPrincipalBytes <= 0 {
		o.MaxPrincipalBytes = 16 << 20
	}
	if o.DefaultRetentionMs <= 0 {
		o.DefaultRetentionMs = 86_400_000
	}
	if o.MaxRetentionMs <= 0 {
		o.MaxRetentionMs = 86_400_000 * 30
	}
	return o
}

// Store keeps metadata in SQLite and payloads under root/objects.
type Store struct {
	db      *sql.DB
	opts    Options
	root    string
	objects string
}

// Open creates schema, confines the objects root, and reconciles orphan files.
func Open(db *sql.DB, opts Options) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("artifact store requires sqlite")
	}
	opts = opts.withDefaults()
	if opts.Root == "" {
		return nil, fmt.Errorf("artifact root is required")
	}
	if opts.MaxArtifactBytes > opts.MaxPrincipalBytes || opts.DefaultRetentionMs > opts.MaxRetentionMs {
		return nil, fmt.Errorf("invalid artifact store bounds")
	}
	if err := os.MkdirAll(opts.Root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(opts.Root)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("artifact root must not be a symbolic link")
	}
	root, err := filepath.EvalSymlinks(opts.Root)
	if err != nil {
		return nil, err
	}
	objects := filepath.Join(root, "objects")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		return nil, err
	}
	objInfo, err := os.Lstat(objects)
	if err != nil {
		return nil, err
	}
	if objInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("artifact objects root is not canonical")
	}
	canon, err := filepath.EvalSymlinks(objects)
	if err != nil || canon != objects {
		return nil, fmt.Errorf("artifact objects root is not canonical")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  logical_name TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
  project_id TEXT,
  environment_id TEXT,
  workspace_id TEXT,
  relative_path TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  retention_ms INTEGER NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS artifacts_principal_created ON artifacts(principal_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS artifacts_expiry ON artifacts(expires_at, id);
`); err != nil {
		return nil, err
	}
	s := &Store{db: db, opts: opts, root: root, objects: objects}
	if err := s.reconcile(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) reconcile() error {
	entries, err := os.ReadDir(s.objects)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(s.objects, name)
		if temporaryFile.MatchString(name) {
			if err := s.assertSafeExisting(path); err != nil {
				return err
			}
			_ = os.Remove(path)
			continue
		}
		if m := tombstoneFile.FindStringSubmatch(name); m != nil {
			if err := s.assertSafeExisting(path); err != nil {
				return err
			}
			var rel string
			err := s.db.QueryRow(`SELECT relative_path FROM artifacts WHERE id = ?`, m[1]).Scan(&rel)
			if err == sql.ErrNoRows {
				_ = os.Remove(path)
				continue
			}
			if err != nil {
				return err
			}
			target, err := s.resolveRelative(rel)
			if err != nil {
				return err
			}
			if _, err := os.Lstat(target); os.IsNotExist(err) {
				if err := os.Rename(path, target); err != nil {
					return err
				}
			} else {
				_ = os.Remove(path)
			}
			continue
		}
		if m := artifactFile.FindStringSubmatch(name); m != nil {
			if err := s.assertSafeExisting(path); err != nil {
				return err
			}
			var rel string
			err := s.db.QueryRow(`SELECT relative_path FROM artifacts WHERE id = ?`, m[1]).Scan(&rel)
			if err == sql.ErrNoRows {
				_ = os.Remove(path)
				continue
			}
			if err != nil {
				return err
			}
			if rel != "objects/"+name {
				return fmt.Errorf("artifact metadata path mismatch")
			}
			continue
		}
		return fmt.Errorf("unexpected file in artifact objects root")
	}
	return nil
}

// Create writes payload then metadata. Quota is enforced per principal.
func (s *Store) Create(principalID, logicalName string, content []byte, workspaceID, projectID, environmentID string, retentionMs int64, now time.Time) (Metadata, error) {
	if err := validatePrincipal(principalID); err != nil {
		return Metadata{}, err
	}
	if !logicalNameRe.MatchString(logicalName) || logicalName == "." || logicalName == ".." {
		return Metadata{}, fail(protocol.ErrorInvalidInput, "invalid artifact logical name")
	}
	for _, value := range []string{projectID, environmentID, workspaceID} {
		if err := validateProvenance(value); err != nil {
			return Metadata{}, err
		}
	}
	if len(content) > s.opts.MaxArtifactBytes {
		return Metadata{}, fail(protocol.ErrorLimitExceeded, "artifact exceeds per-artifact quota")
	}
	if retentionMs <= 0 {
		retentionMs = s.opts.DefaultRetentionMs
	}
	if retentionMs <= 0 || retentionMs > s.opts.MaxRetentionMs {
		return Metadata{}, fail(protocol.ErrorInvalidInput, "invalid artifact retention")
	}
	if now.IsZero() {
		now = time.Now()
	}
	id := newArtifactID()
	tx, err := s.db.Begin()
	if err != nil {
		return Metadata{}, err
	}
	committedFile := false
	var staged stagedArtifact
	defer func() {
		if staged.temporaryPath != "" {
			s.discardStage(staged, committedFile)
		}
	}()
	var used int
	if err := tx.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM artifacts WHERE principal_id = ?`, principalID).Scan(&used); err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	if used+len(content) > s.opts.MaxPrincipalBytes {
		_ = tx.Rollback()
		return Metadata{}, fail(protocol.ErrorLimitExceeded, "artifact quota exceeded")
	}
	staged, err = s.stage(id, content)
	if err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	if err := s.commitStage(staged); err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	committedFile = true
	sum := sha256.Sum256(content)
	expires := now.Add(time.Duration(retentionMs) * time.Millisecond)
	if _, err := tx.Exec(`INSERT INTO artifacts
		(id, principal_id, logical_name, sha256, size_bytes, project_id, environment_id, workspace_id,
		 relative_path, created_at, updated_at, expires_at, retention_ms, generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		id, principalID, logicalName, hex.EncodeToString(sum[:]), len(content),
		nullString(projectID), nullString(environmentID), nullString(workspaceID),
		staged.relativePath, now.UnixMilli(), now.UnixMilli(), expires.UnixMilli(), retentionMs); err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	staged.temporaryPath = ""
	return s.metadata(principalID, id, now)
}

func (s *Store) metadata(principalID, artifactID string, now time.Time) (Metadata, error) {
	row, err := s.rowByOwner(principalID, artifactID)
	if err != nil {
		return Metadata{}, err
	}
	if !row.ExpiresAt.After(now) {
		return Metadata{}, fail(protocol.ErrorNotFound, "artifact not found")
	}
	return row, nil
}

// Metadata returns an unexpired principal-owned artifact.
func (s *Store) Metadata(principalID, artifactID string, now time.Time) (Metadata, error) {
	if err := validatePrincipal(principalID); err != nil {
		return Metadata{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	return s.metadata(principalID, artifactID, now)
}

// Chunk is one base64 payload page.
type Chunk struct {
	ArtifactID    string
	LogicalName   string
	Offset        int
	BytesReturned int
	TotalBytes    int
	SHA256        string
	EOF           bool
	Content       string
}

// Read returns a bounded base64 chunk. Expired or foreign ids are NOT_FOUND.
func (s *Store) Read(principalID, artifactID string, offset, limit int, now time.Time) (Chunk, error) {
	if err := validatePrincipal(principalID); err != nil {
		return Chunk{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	row, err := s.rowByOwner(principalID, artifactID)
	if err != nil {
		return Chunk{}, err
	}
	if !row.ExpiresAt.After(now) {
		return Chunk{}, fail(protocol.ErrorNotFound, "artifact not found")
	}
	if offset < 0 {
		return Chunk{}, fail(protocol.ErrorInvalidInput, "invalid artifact offset")
	}
	if limit <= 0 {
		limit = 65_536
	}
	if limit < 1 || limit > 1_048_576 {
		return Chunk{}, fail(protocol.ErrorInvalidInput, "invalid artifact limit")
	}
	path, err := s.resolveExisting(row.relativePath)
	if err != nil {
		return Chunk{}, fail(protocol.ErrorNotFound, "artifact payload verification failed")
	}
	if offset >= row.SizeBytes {
		return Chunk{
			ArtifactID: row.ArtifactID, LogicalName: row.LogicalName, Offset: offset,
			BytesReturned: 0, TotalBytes: row.SizeBytes, SHA256: row.SHA256, EOF: true, Content: "",
		}, nil
	}
	readLen := limit
	if readLen > row.SizeBytes-offset {
		readLen = row.SizeBytes - offset
	}
	f, err := os.Open(path)
	if err != nil {
		return Chunk{}, fail(protocol.ErrorNotFound, "artifact payload verification failed")
	}
	defer f.Close()
	buf := make([]byte, readLen)
	n, err := f.ReadAt(buf, int64(offset))
	if err != nil && err != io.EOF {
		return Chunk{}, fail(protocol.ErrorNotFound, "artifact payload verification failed")
	}
	if n != readLen {
		return Chunk{}, fail(protocol.ErrorNotFound, "artifact payload verification failed")
	}
	return Chunk{
		ArtifactID: row.ArtifactID, LogicalName: row.LogicalName, Offset: offset,
		BytesReturned: n, TotalBytes: row.SizeBytes, SHA256: row.SHA256,
		EOF: offset+n >= row.SizeBytes, Content: base64.StdEncoding.EncodeToString(buf),
	}, nil
}

// Payload is the verified full bytes for restore.
type Payload struct {
	Metadata Metadata
	Content  []byte
}

// ReadPayload verifies sha256 and size against metadata.
func (s *Store) ReadPayload(principalID, artifactID string, now time.Time) (Payload, error) {
	if err := validatePrincipal(principalID); err != nil {
		return Payload{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	row, err := s.rowByOwner(principalID, artifactID)
	if err != nil {
		return Payload{}, err
	}
	if !row.ExpiresAt.After(now) {
		return Payload{}, fail(protocol.ErrorNotFound, "artifact not found")
	}
	path, err := s.resolveExisting(row.relativePath)
	if err != nil {
		return Payload{}, fail(protocol.ErrorNotFound, "artifact payload verification failed")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Payload{}, fail(protocol.ErrorNotFound, "artifact payload verification failed")
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != row.SHA256 || len(content) != row.SizeBytes {
		return Payload{}, fail(protocol.ErrorNotFound, "artifact payload verification failed")
	}
	return Payload{Metadata: row, Content: content}, nil
}

// Page is a bounded list of unexpired artifacts.
type Page struct {
	Artifacts []Metadata
	Cursor    string
}

// List pages principal-owned unexpired artifacts newest first.
func (s *Store) List(principalID string, limit int, cursor string, now time.Time) (Page, error) {
	if err := validatePrincipal(principalID); err != nil {
		return Page{}, err
	}
	if limit < 1 || limit > 100 {
		return Page{}, fail(protocol.ErrorInvalidInput, "invalid artifact page limit")
	}
	if now.IsZero() {
		now = time.Now()
	}
	var cursorAt sql.NullInt64
	var cursorID sql.NullString
	if cursor != "" {
		decoded, err := decodeCursor(cursor)
		if err != nil {
			return Page{}, err
		}
		cursorAt = sql.NullInt64{Int64: decoded.createdAt, Valid: true}
		cursorID = sql.NullString{String: decoded.artifactID, Valid: true}
	}
	rows, err := s.db.Query(`SELECT id, principal_id, logical_name, sha256, size_bytes, project_id, environment_id, workspace_id, relative_path, created_at, updated_at, expires_at, retention_ms, generation
		FROM artifacts
		WHERE principal_id = ? AND expires_at > ?
		  AND (? IS NULL OR created_at < ? OR (created_at = ? AND id < ?))
		ORDER BY created_at DESC, id DESC LIMIT ?`,
		principalID, now.UnixMilli(),
		nullInt(cursorAt), nullInt(cursorAt), nullInt(cursorAt), nullString(cursorID.String),
		limit+1)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	var out []Metadata
	for rows.Next() {
		rec, err := scanMetadata(rows)
		if err != nil {
			return Page{}, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	page := Page{Artifacts: out}
	if len(out) > limit {
		page.Artifacts = out[:limit]
		page.Cursor = encodeCursor(page.Artifacts[len(page.Artifacts)-1])
	}
	return page, nil
}

// Delete removes metadata then the object. Generation must match.
func (s *Store) Delete(principalID, artifactID string, expectedGeneration int) (Metadata, error) {
	if err := validatePrincipal(principalID); err != nil {
		return Metadata{}, err
	}
	if expectedGeneration < 1 {
		expectedGeneration = 1
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Metadata{}, err
	}
	row, err := s.rowByOwnerTx(tx, principalID, artifactID)
	if err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	if row.Generation != expectedGeneration {
		_ = tx.Rollback()
		return Metadata{}, fail(protocol.ErrorConflict, "artifact generation changed")
	}
	target, err := s.resolveRelative(row.relativePath)
	if err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	if err := s.assertSafeExisting(target); err != nil {
		_ = tx.Rollback()
		return Metadata{}, fail(protocol.ErrorNotFound, "artifact not found")
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	tombstone := filepath.Join(s.objects, fmt.Sprintf(".deleting-%s-%d-%s", row.ArtifactID, row.Generation, hex.EncodeToString(nonce)))
	if err := os.Rename(target, tombstone); err != nil {
		_ = tx.Rollback()
		return Metadata{}, err
	}
	res, err := tx.Exec(`DELETE FROM artifacts WHERE principal_id = ? AND id = ? AND generation = ?`, principalID, artifactID, expectedGeneration)
	if err != nil {
		_ = os.Rename(tombstone, target)
		_ = tx.Rollback()
		return Metadata{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		_ = os.Rename(tombstone, target)
		_ = tx.Rollback()
		return Metadata{}, fail(protocol.ErrorConflict, "artifact generation changed")
	}
	if err := tx.Commit(); err != nil {
		_ = os.Rename(tombstone, target)
		return Metadata{}, err
	}
	_ = os.Remove(tombstone)
	return row, nil
}

type stagedArtifact struct {
	temporaryPath string
	targetPath    string
	relativePath  string
}

func (s *Store) stage(id string, content []byte) (stagedArtifact, error) {
	rel := "objects/" + id + ".snapshot"
	target, err := s.resolveRelative(rel)
	if err != nil {
		return stagedArtifact{}, err
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return stagedArtifact{}, err
	}
	tmp := filepath.Join(s.objects, ".tmp-"+id+"-"+hex.EncodeToString(nonce))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return stagedArtifact{}, err
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return stagedArtifact{}, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return stagedArtifact{}, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return stagedArtifact{}, err
	}
	return stagedArtifact{temporaryPath: tmp, targetPath: target, relativePath: rel}, nil
}

func (s *Store) commitStage(st stagedArtifact) error {
	if err := os.Link(st.temporaryPath, st.targetPath); err != nil {
		return err
	}
	return os.Remove(st.temporaryPath)
}

func (s *Store) discardStage(st stagedArtifact, committed bool) {
	if st.temporaryPath != "" {
		_ = os.Remove(st.temporaryPath)
	}
	if committed && st.targetPath != "" {
		_ = os.Remove(st.targetPath)
	}
}

func (s *Store) resolveRelative(rel string) (string, error) {
	if !relativeSafe.MatchString(rel) {
		return "", fmt.Errorf("unsafe artifact storage path")
	}
	target := filepath.Join(s.root, filepath.FromSlash(rel))
	if !strings.HasPrefix(target, s.objects+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe artifact storage path")
	}
	return target, nil
}

func (s *Store) resolveExisting(rel string) (string, error) {
	target, err := s.resolveRelative(rel)
	if err != nil {
		return "", err
	}
	if err := s.assertSafeExisting(target); err != nil {
		return "", err
	}
	return target, nil
}

func (s *Store) assertSafeExisting(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe artifact storage path")
	}
	actual, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(actual, s.objects+string(os.PathSeparator)) {
		return fmt.Errorf("unsafe artifact storage path")
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanMetadata(row scanner) (Metadata, error) {
	var rec Metadata
	var principal, rel string
	var project, env, workspace sql.NullString
	var created, updated, expires, retention int64
	if err := row.Scan(&rec.ArtifactID, &principal, &rec.LogicalName, &rec.SHA256, &rec.SizeBytes, &project, &env, &workspace, &rel, &created, &updated, &expires, &retention, &rec.Generation); err != nil {
		return Metadata{}, err
	}
	rec.ProjectID = project.String
	rec.EnvironmentID = env.String
	rec.WorkspaceID = workspace.String
	rec.relativePath = rel
	rec.CreatedAt = time.UnixMilli(created)
	rec.UpdatedAt = time.UnixMilli(updated)
	rec.ExpiresAt = time.UnixMilli(expires)
	rec.RetentionMs = retention
	return rec, nil
}

// relativePath is stored on Metadata privately via embedding workaround.
func (s *Store) rowByOwner(principalID, artifactID string) (Metadata, error) {
	row := s.db.QueryRow(`SELECT id, principal_id, logical_name, sha256, size_bytes, project_id, environment_id, workspace_id, relative_path, created_at, updated_at, expires_at, retention_ms, generation
		FROM artifacts WHERE principal_id = ? AND id = ?`, principalID, artifactID)
	rec, err := scanMetadata(row)
	if err == sql.ErrNoRows {
		return Metadata{}, fail(protocol.ErrorNotFound, "artifact not found")
	}
	if err != nil {
		return Metadata{}, err
	}
	return rec, nil
}

func (s *Store) rowByOwnerTx(tx *sql.Tx, principalID, artifactID string) (Metadata, error) {
	row := tx.QueryRow(`SELECT id, principal_id, logical_name, sha256, size_bytes, project_id, environment_id, workspace_id, relative_path, created_at, updated_at, expires_at, retention_ms, generation
		FROM artifacts WHERE principal_id = ? AND id = ?`, principalID, artifactID)
	rec, err := scanMetadata(row)
	if err == sql.ErrNoRows {
		return Metadata{}, fail(protocol.ErrorNotFound, "artifact not found")
	}
	if err != nil {
		return Metadata{}, err
	}
	return rec, nil
}

func validatePrincipal(id string) error {
	if id == "" || len(id) > 200 {
		return fail(protocol.ErrorInvalidInput, "invalid artifact principal")
	}
	return nil
}

func validateProvenance(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 200 {
		return fail(protocol.ErrorInvalidInput, "invalid artifact provenance")
	}
	for _, r := range value {
		if r <= 31 || r == 127 {
			return fail(protocol.ErrorInvalidInput, "invalid artifact provenance")
		}
	}
	return nil
}

func encodeCursor(row Metadata) string {
	raw, _ := json.Marshal(map[string]any{"createdAt": row.CreatedAt.UnixMilli(), "artifactId": row.ArtifactID})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(value string) (struct {
	createdAt  int64
	artifactID string
}, error) {
	var out struct {
		createdAt  int64
		artifactID string
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return out, fail(protocol.ErrorInvalidInput, "invalid artifact cursor")
	}
	var parsed struct {
		CreatedAt  json.Number `json:"createdAt"`
		ArtifactID string      `json:"artifactId"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out, fail(protocol.ErrorInvalidInput, "invalid artifact cursor")
	}
	n, err := parsed.CreatedAt.Int64()
	if err != nil || !cursorIDRe.MatchString(parsed.ArtifactID) {
		return out, fail(protocol.ErrorInvalidInput, "invalid artifact cursor")
	}
	out.createdAt = n
	out.artifactID = parsed.ArtifactID
	return out, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func newArtifactID() string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		panic("artifacts: crypto/rand unavailable")
	}
	return "art_" + base64.RawURLEncoding.EncodeToString(buf)
}
