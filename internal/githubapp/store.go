package githubapp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const maxStatesPerPrincipal = 8

var ErrConflict = fmt.Errorf("conflict")
var ErrInvalidSetup = fmt.Errorf("invalid")

type Installation struct {
	PrincipalID    string
	AppID          string
	InstallationID string
	AccountID      string
	AccountLogin   string
	Issues         string
	PullRequests   string
	Status         string
	Generation     int
	CreatedAt      int64
	UpdatedAt      int64
	CheckedAt      int64
}

func (i Installation) PublicJSON() map[string]any {
	return map[string]any{
		"appId":          i.AppID,
		"installationId": i.InstallationID,
		"accountId":      i.AccountID,
		"accountLogin":   i.AccountLogin,
		"status":         i.Status,
		"generation":     i.Generation,
		"createdAt":      i.CreatedAt,
		"updatedAt":      i.UpdatedAt,
		"checkedAt":      i.CheckedAt,
	}
}

type RepositoryGrant struct {
	PrincipalID    string
	InstallationID string
	Owner          string
	Repository     string
	Contents       string
	Status         string
	Generation     int
	CreatedAt      int64
	UpdatedAt      int64
	CheckedAt      int64
}

func (g RepositoryGrant) PublicJSON() map[string]any {
	return map[string]any{
		"installationId": g.InstallationID,
		"owner":          g.Owner,
		"repository":     g.Repository,
		"contents":       g.Contents,
		"status":         g.Status,
		"generation":     g.Generation,
		"createdAt":      g.CreatedAt,
		"updatedAt":      g.UpdatedAt,
		"checkedAt":      g.CheckedAt,
	}
}

type Verified struct {
	AppID          string
	InstallationID string
	AccountID      string
	AccountLogin   string
	Issues         string
	PullRequests   string
	Status         string
	Repositories   []VerifiedRepo
}

type VerifiedRepo struct {
	Owner      string
	Repository string
	Contents   string
}

type SetupState struct {
	PrincipalID       string
	ExpectedAppID     string
	ExpectedAccountID string
	ExpiresAt         int64
}

type Store struct {
	db *sql.DB
}

func Open(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("github app store requires sqlite")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS github_installations (
  principal_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  installation_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  account_login TEXT NOT NULL,
  issues TEXT,
  pull_requests TEXT,
  status TEXT NOT NULL CHECK(status IN ('active','suspended','uninstalled')),
  generation INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  checked_at INTEGER NOT NULL,
  PRIMARY KEY(principal_id, installation_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS github_installations_principal_account
  ON github_installations(principal_id, account_id);
CREATE UNIQUE INDEX IF NOT EXISTS github_installations_installation_identity
  ON github_installations(installation_id);
CREATE TABLE IF NOT EXISTS github_repository_grants (
  principal_id TEXT NOT NULL,
  installation_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  repository TEXT NOT NULL,
  contents TEXT NOT NULL CHECK(contents IN ('read','write')),
  status TEXT NOT NULL CHECK(status IN ('granted','removed')),
  generation INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  checked_at INTEGER NOT NULL,
  PRIMARY KEY(principal_id, owner, repository)
);
CREATE INDEX IF NOT EXISTS github_repository_grants_principal_installation
  ON github_repository_grants(principal_id, installation_id);
CREATE TABLE IF NOT EXISTS github_setup_states (
  state_hash TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  expected_app_id TEXT NOT NULL,
  expected_account_id TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS github_setup_states_principal_expiry
  ON github_setup_states(principal_id, expires_at, created_at);
`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) CreateSetup(principalID, expectedAppID, expectedAccountID string, ttlMs int64) (state string, expiresAt int64, err error) {
	if ttlMs <= 0 {
		ttlMs = 10 * 60_000
	}
	now := time.Now().UnixMilli()
	expiresAt = now + ttlMs
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", 0, err
	}
	state = base64.RawURLEncoding.EncodeToString(raw)
	hash := hashState(state)
	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM github_setup_states WHERE expires_at <= ?`, now); err != nil {
		return "", 0, err
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM github_setup_states WHERE principal_id = ?`, principalID).Scan(&count); err != nil {
		return "", 0, err
	}
	excess := count - maxStatesPerPrincipal + 1
	if excess > 0 {
		if _, err := tx.Exec(`DELETE FROM github_setup_states WHERE state_hash IN (
			SELECT state_hash FROM github_setup_states WHERE principal_id = ? ORDER BY expires_at ASC, created_at ASC LIMIT ?
		)`, principalID, excess); err != nil {
			return "", 0, err
		}
	}
	var account any
	if expectedAccountID != "" {
		account = expectedAccountID
	}
	if _, err := tx.Exec(`INSERT INTO github_setup_states
		(state_hash, principal_id, expected_app_id, expected_account_id, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, hash, principalID, expectedAppID, account, expiresAt, now); err != nil {
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	return state, expiresAt, nil
}

func (s *Store) ConsumeSetup(state, principalID string) (SetupState, error) {
	now := time.Now().UnixMilli()
	hash := hashState(state)
	tx, err := s.db.Begin()
	if err != nil {
		return SetupState{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM github_setup_states WHERE expires_at <= ?`, now); err != nil {
		return SetupState{}, err
	}
	var rec SetupState
	var account sql.NullString
	err = tx.QueryRow(`SELECT principal_id, expected_app_id, expected_account_id, expires_at
		FROM github_setup_states WHERE state_hash = ? AND principal_id = ? AND expires_at > ?`,
		hash, principalID, now).Scan(&rec.PrincipalID, &rec.ExpectedAppID, &account, &rec.ExpiresAt)
	if err == sql.ErrNoRows {
		_ = tx.Commit()
		return SetupState{}, ErrInvalidSetup
	}
	if err != nil {
		return SetupState{}, err
	}
	res, err := tx.Exec(`DELETE FROM github_setup_states WHERE state_hash = ? AND principal_id = ?`, hash, principalID)
	if err != nil {
		return SetupState{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return SetupState{}, ErrInvalidSetup
	}
	if err := tx.Commit(); err != nil {
		return SetupState{}, err
	}
	if account.Valid {
		rec.ExpectedAccountID = account.String
	}
	return rec, nil
}

func (s *Store) ReplaceVerified(principalID string, verified Verified, checkedAt int64) (Installation, error) {
	if checkedAt <= 0 {
		checkedAt = time.Now().UnixMilli()
	}
	installationID := strings.TrimSpace(verified.InstallationID)
	accountID := strings.TrimSpace(verified.AccountID)
	tx, err := s.db.Begin()
	if err != nil {
		return Installation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var other string
	err = tx.QueryRow(`SELECT principal_id FROM github_installations WHERE installation_id = ? AND principal_id <> ?`,
		installationID, principalID).Scan(&other)
	if err == nil {
		return Installation{}, ErrConflict
	}
	if err != nil && err != sql.ErrNoRows {
		return Installation{}, err
	}
	var sameAccount string
	err = tx.QueryRow(`SELECT installation_id FROM github_installations WHERE principal_id = ? AND account_id = ? AND installation_id <> ?`,
		principalID, accountID, installationID).Scan(&sameAccount)
	if err == nil {
		if _, err := tx.Exec(`DELETE FROM github_installations WHERE principal_id = ? AND installation_id = ?`, principalID, sameAccount); err != nil {
			return Installation{}, err
		}
		if _, err := tx.Exec(`UPDATE github_repository_grants SET status='removed', generation=generation+1, updated_at=?, checked_at=?
			WHERE principal_id = ? AND installation_id = ? AND status <> 'removed'`, checkedAt, checkedAt, principalID, sameAccount); err != nil {
			return Installation{}, err
		}
	} else if err != sql.ErrNoRows {
		return Installation{}, err
	}
	prior, _ := s.getInstallationTx(tx, principalID, installationID)
	rec := Installation{
		PrincipalID: principalID, AppID: strings.TrimSpace(verified.AppID), InstallationID: installationID,
		AccountID: accountID, AccountLogin: verified.AccountLogin, Status: verified.Status,
		Issues: verified.Issues, PullRequests: verified.PullRequests,
		Generation: 1, CreatedAt: checkedAt, UpdatedAt: checkedAt, CheckedAt: checkedAt,
	}
	if prior != nil {
		rec.Generation = prior.Generation + 1
		rec.CreatedAt = prior.CreatedAt
	}
	if rec.Status == "" {
		rec.Status = "active"
	}
	if _, err := tx.Exec(`INSERT INTO github_installations
		(principal_id, app_id, installation_id, account_id, account_login, issues, pull_requests, status, generation, created_at, updated_at, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(principal_id, installation_id) DO UPDATE SET
		app_id=excluded.app_id, account_id=excluded.account_id, account_login=excluded.account_login,
		issues=excluded.issues, pull_requests=excluded.pull_requests,
		status=excluded.status, generation=excluded.generation, updated_at=excluded.updated_at, checked_at=excluded.checked_at`,
		rec.PrincipalID, rec.AppID, rec.InstallationID, rec.AccountID, rec.AccountLogin, nullEmpty(rec.Issues), nullEmpty(rec.PullRequests),
		rec.Status, rec.Generation, rec.CreatedAt, rec.UpdatedAt, rec.CheckedAt); err != nil {
		return Installation{}, err
	}
	current := map[string]struct{}{}
	if rec.Status == "active" {
		for _, repo := range verified.Repositories {
			owner := strings.ToLower(repo.Owner)
			name := strings.ToLower(repo.Repository)
			current[owner+"\x00"+name] = struct{}{}
			previous, _ := s.getGrantTx(tx, principalID, owner, name)
			gen := 1
			created := checkedAt
			if previous != nil {
				gen = previous.Generation + 1
				created = previous.CreatedAt
			}
			if _, err := tx.Exec(`INSERT INTO github_repository_grants
				(principal_id, installation_id, owner, repository, contents, status, generation, created_at, updated_at, checked_at)
				VALUES (?, ?, ?, ?, ?, 'granted', ?, ?, ?, ?)
				ON CONFLICT(principal_id, owner, repository) DO UPDATE SET
				installation_id=excluded.installation_id, contents=excluded.contents, status='granted',
				generation=excluded.generation, updated_at=excluded.updated_at, checked_at=excluded.checked_at`,
				principalID, rec.InstallationID, owner, name, repo.Contents, gen, created, checkedAt, checkedAt); err != nil {
				return Installation{}, err
			}
		}
	}
	existing, err := s.listGrantsTx(tx, principalID, rec.InstallationID)
	if err != nil {
		return Installation{}, err
	}
	for _, grant := range existing {
		if grant.Status != "removed" {
			if _, ok := current[grant.Owner+"\x00"+grant.Repository]; !ok {
				if _, err := tx.Exec(`UPDATE github_repository_grants SET status='removed', generation=generation+1, updated_at=?, checked_at=?
					WHERE principal_id=? AND installation_id=? AND owner=? AND repository=?`,
					checkedAt, checkedAt, principalID, rec.InstallationID, grant.Owner, grant.Repository); err != nil {
					return Installation{}, err
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return Installation{}, err
	}
	return rec, nil
}

func (s *Store) MarkUninstalled(principalID, installationID string, checkedAt int64) (*Installation, error) {
	current, err := s.GetInstallation(principalID, installationID)
	if err != nil || current == nil {
		return current, err
	}
	rec, err := s.ReplaceVerified(principalID, Verified{
		AppID: current.AppID, InstallationID: current.InstallationID, AccountID: current.AccountID,
		AccountLogin: current.AccountLogin, Issues: current.Issues, PullRequests: current.PullRequests,
		Status: "uninstalled",
	}, checkedAt)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) RemoveInstallation(principalID, installationID string, checkedAt int64) (*Installation, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := s.getInstallationTx(tx, principalID, installationID)
	if err != nil {
		return nil, false, err
	}
	if current == nil {
		return nil, false, nil
	}
	if _, err := tx.Exec(`DELETE FROM github_installations WHERE principal_id=? AND installation_id=?`, principalID, installationID); err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(`UPDATE github_repository_grants SET status='removed', generation=generation+1, updated_at=?, checked_at=?
		WHERE principal_id=? AND installation_id=? AND status<>'removed'`, checkedAt, checkedAt, principalID, installationID); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return current, true, nil
}

func (s *Store) GetInstallation(principalID, installationID string) (*Installation, error) {
	if installationID != "" {
		return s.getInstallationTx(s.db, principalID, installationID)
	}
	row := s.db.QueryRow(`SELECT principal_id, app_id, installation_id, account_id, account_login, issues, pull_requests, status, generation, created_at, updated_at, checked_at
		FROM github_installations WHERE principal_id=? ORDER BY (CASE status WHEN 'active' THEN 0 WHEN 'suspended' THEN 1 ELSE 2 END), created_at ASC LIMIT 1`, principalID)
	return scanInstallation(row)
}

func (s *Store) ListInstallations(principalID string) ([]Installation, error) {
	rows, err := s.db.Query(`SELECT principal_id, app_id, installation_id, account_id, account_login, issues, pull_requests, status, generation, created_at, updated_at, checked_at
		FROM github_installations WHERE principal_id=? ORDER BY created_at ASC`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Installation, 0)
	for rows.Next() {
		rec, err := scanInstallationRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) ListRepositoryGrants(principalID, installationID string) ([]RepositoryGrant, error) {
	if installationID != "" {
		return s.listGrantsTx(s.db, principalID, installationID)
	}
	rows, err := s.db.Query(`SELECT principal_id, installation_id, owner, repository, contents, status, generation, created_at, updated_at, checked_at
		FROM github_repository_grants WHERE principal_id=? ORDER BY owner, repository`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

func (s *Store) getInstallationTx(q queryer, principalID, installationID string) (*Installation, error) {
	row := q.QueryRow(`SELECT principal_id, app_id, installation_id, account_id, account_login, issues, pull_requests, status, generation, created_at, updated_at, checked_at
		FROM github_installations WHERE principal_id=? AND installation_id=?`, principalID, installationID)
	return scanInstallation(row)
}

func (s *Store) getGrantTx(q queryer, principalID, owner, repository string) (*RepositoryGrant, error) {
	row := q.QueryRow(`SELECT principal_id, installation_id, owner, repository, contents, status, generation, created_at, updated_at, checked_at
		FROM github_repository_grants WHERE principal_id=? AND owner=? AND repository=?`, principalID, owner, repository)
	var g RepositoryGrant
	err := row.Scan(&g.PrincipalID, &g.InstallationID, &g.Owner, &g.Repository, &g.Contents, &g.Status, &g.Generation, &g.CreatedAt, &g.UpdatedAt, &g.CheckedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) listGrantsTx(q queryer, principalID, installationID string) ([]RepositoryGrant, error) {
	rows, err := q.Query(`SELECT principal_id, installation_id, owner, repository, contents, status, generation, created_at, updated_at, checked_at
		FROM github_repository_grants WHERE principal_id=? AND installation_id=? ORDER BY owner, repository`, principalID, installationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanInstallation(row rowScanner) (*Installation, error) {
	var rec Installation
	var issues, prs sql.NullString
	err := row.Scan(&rec.PrincipalID, &rec.AppID, &rec.InstallationID, &rec.AccountID, &rec.AccountLogin, &issues, &prs, &rec.Status, &rec.Generation, &rec.CreatedAt, &rec.UpdatedAt, &rec.CheckedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec.Issues = issues.String
	rec.PullRequests = prs.String
	return &rec, nil
}

func scanInstallationRow(rows *sql.Rows) (Installation, error) {
	rec, err := scanInstallation(rows)
	if err != nil || rec == nil {
		return Installation{}, err
	}
	return *rec, nil
}

func scanGrants(rows *sql.Rows) ([]RepositoryGrant, error) {
	out := make([]RepositoryGrant, 0)
	for rows.Next() {
		var g RepositoryGrant
		if err := rows.Scan(&g.PrincipalID, &g.InstallationID, &g.Owner, &g.Repository, &g.Contents, &g.Status, &g.Generation, &g.CreatedAt, &g.UpdatedAt, &g.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func hashState(state string) string {
	sum := sha256.Sum256([]byte(state))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func SameID(expected, actual string) bool {
	left := []byte(expected)
	right := []byte(actual)
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare(left, right) == 1
}

func nullEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
