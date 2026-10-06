package models

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

const credentialEnvironment = "model_provider_credential"

var (
	ErrNotFound = fmt.Errorf("not found")
	ErrConflict = fmt.Errorf("conflict")
	ErrInvalid  = fmt.Errorf("invalid")
)

var allowedProviders = map[string]struct{}{
	"openai": {}, "anthropic": {}, "openrouter": {}, "google": {}, "custom": {},
}
var allowedAuthModes = map[string]struct{}{"bearer": {}, "x-api-key": {}}
var allowedAPIModes = map[string]struct{}{"chat-completions": {}, "responses": {}}
var allowedProxyOps = map[string]struct{}{
	"files_list": {}, "files_read": {}, "files_write": {}, "files_apply_patch": {},
	"files_delete": {}, "files_move": {}, "files_mkdir": {}, "grep_search": {},
	"symbols_search": {}, "symbols_references": {},
}

// Credential is dashboard-visible provider credential metadata. apiKey is never included.
type Credential struct {
	ID            string
	PrincipalID   string
	Label         string
	Provider      string
	AuthMode      string
	ActiveVersion int
	Status        string
	SyncStatus    string
	Generation    int
	CreatedAt     int64
	UpdatedAt     int64
}

// PublicJSON drops principalId and never includes apiKey.
func (c Credential) PublicJSON() map[string]any {
	return map[string]any{
		"id":            c.ID,
		"label":         c.Label,
		"provider":      c.Provider,
		"authMode":      c.AuthMode,
		"activeVersion": c.ActiveVersion,
		"status":        c.Status,
		"syncStatus":    c.SyncStatus,
		"createdAt":     c.CreatedAt,
		"updatedAt":     c.UpdatedAt,
	}
}

// Revision is an immutable profile revision.
type Revision struct {
	ID                 string
	ProfileID          string
	PrincipalID        string
	CredentialID       string
	Model              string
	APIMode            string
	DownstreamPath     string
	UpstreamURL        string
	Pricing            map[string]any
	Limits             map[string]any
	MaxProxyOperations []string
	Digest             string
	CreatedAt          int64
}

func (r Revision) PublicJSON() map[string]any {
	return map[string]any{
		"id":                 r.ID,
		"profileId":          r.ProfileID,
		"credentialId":       r.CredentialID,
		"model":              r.Model,
		"apiMode":            r.APIMode,
		"downstreamPath":     r.DownstreamPath,
		"upstreamUrl":        r.UpstreamURL,
		"pricing":            r.Pricing,
		"limits":             r.Limits,
		"maxProxyOperations": r.MaxProxyOperations,
		"digest":             r.Digest,
		"createdAt":          r.CreatedAt,
	}
}

// Profile is dashboard-visible agent model profile metadata.
type Profile struct {
	ID                string
	PrincipalID       string
	DisplayName       string
	CredentialID      string
	DesiredRevisionID *string
	ActiveRevisionID  *string
	Generation        int
	Status            string
	ActiveRevision    *Revision
	CreatedAt         int64
	UpdatedAt         int64
}

func (p Profile) PublicJSON() map[string]any {
	var desired, active, revision any
	if p.DesiredRevisionID != nil {
		desired = *p.DesiredRevisionID
	}
	if p.ActiveRevisionID != nil {
		active = *p.ActiveRevisionID
	}
	if p.ActiveRevision != nil {
		revision = p.ActiveRevision.PublicJSON()
	}
	return map[string]any{
		"id":                p.ID,
		"displayName":       p.DisplayName,
		"credentialId":      p.CredentialID,
		"desiredRevisionId": desired,
		"activeRevisionId":  active,
		"generation":        p.Generation,
		"status":            p.Status,
		"activeRevision":    revision,
		"createdAt":         p.CreatedAt,
		"updatedAt":         p.UpdatedAt,
	}
}

// Store persists encrypted provider credentials and immutable profile revisions.
type Store struct {
	db      *sql.DB
	keyring *secrets.Keyring
}

// Open creates model credential/profile tables if missing.
func Open(db *sql.DB, keyring *secrets.Keyring) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("model store requires sqlite")
	}
	if keyring == nil {
		return nil, fmt.Errorf("model profile operations are temporarily unavailable")
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS model_provider_credentials (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  label TEXT NOT NULL,
  provider TEXT NOT NULL,
  auth_mode TEXT NOT NULL,
  active_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'DISABLED', 'REVOKED')),
  generation INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS model_creds_principal_idx ON model_provider_credentials(principal_id, created_at DESC);
CREATE TABLE IF NOT EXISTS model_provider_credential_versions (
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
CREATE TABLE IF NOT EXISTS agent_model_profiles (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  desired_revision_id TEXT,
  active_revision_id TEXT,
  generation INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'DISABLED', 'SYNC_PENDING', 'SYNC_FAILED')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_profiles_principal_idx ON agent_model_profiles(principal_id, created_at DESC);
CREATE TABLE IF NOT EXISTS agent_model_profile_revisions (
  id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  model TEXT NOT NULL,
  api_mode TEXT NOT NULL,
  downstream_path TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  input_micros_per_million INTEGER NOT NULL,
  output_micros_per_million INTEGER NOT NULL,
  max_input_tokens INTEGER NOT NULL,
  max_output_tokens INTEGER NOT NULL,
  max_cost_micros INTEGER NOT NULL,
  max_proxy_operations_json TEXT NOT NULL,
  digest TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_revisions_profile_idx ON agent_model_profile_revisions(profile_id, created_at DESC);
`); err != nil {
		return nil, err
	}
	return &Store{db: db, keyring: keyring}, nil
}

func normalizeLabel(label string) (string, error) {
	value := strings.TrimSpace(label)
	if value == "" || len(value) > 100 {
		return "", fmt.Errorf("%w: label must contain 1 to 100 characters", ErrInvalid)
	}
	return value, nil
}

func normalizeProvider(provider string) (string, error) {
	if _, ok := allowedProviders[provider]; !ok {
		return "", fmt.Errorf("%w: unsupported provider", ErrInvalid)
	}
	return provider, nil
}

func normalizeAuthMode(mode, provider string) (string, error) {
	if mode == "" {
		return "bearer", nil
	}
	if _, ok := allowedAuthModes[mode]; !ok {
		return "", fmt.Errorf("%w: unsupported authMode", ErrInvalid)
	}
	return mode, nil
}

func validateAPIKey(apiKey string) error {
	if len(apiKey) < 1 || len(apiKey) > 4096 {
		return fmt.Errorf("%w: apiKey is invalid", ErrInvalid)
	}
	return nil
}

// CreateCredential encrypts apiKey. The returned view never includes it.
func (s *Store) CreateCredential(principalID, label, provider, authMode, apiKey string, now int64) (Credential, error) {
	label, err := normalizeLabel(label)
	if err != nil {
		return Credential{}, err
	}
	provider, err = normalizeProvider(provider)
	if err != nil {
		return Credential{}, err
	}
	authMode, err = normalizeAuthMode(authMode, provider)
	if err != nil {
		return Credential{}, err
	}
	if err := validateAPIKey(apiKey); err != nil {
		return Credential{}, err
	}
	id := protocol.NewOpaqueID(protocol.PrefixModelCredential)
	enc, err := s.keyring.EncryptString(apiKey, secrets.Context{
		PrincipalID: principalID, EnvironmentID: credentialEnvironment, Name: id, Version: 1,
	})
	if err != nil {
		return Credential{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Credential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO model_provider_credentials
		(id, principal_id, label, provider, auth_mode, active_version, status, generation, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, 'ACTIVE', 1, ?, ?)`,
		id, principalID, label, provider, authMode, now, now); err != nil {
		return Credential{}, err
	}
	if _, err := tx.Exec(`INSERT INTO model_provider_credential_versions
		(principal_id, credential_id, version, key_version, nonce, ciphertext, auth_tag, created_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?)`,
		principalID, id, enc.KeyVersion, enc.Nonce, enc.Ciphertext, enc.AuthTag, now); err != nil {
		return Credential{}, err
	}
	if err := tx.Commit(); err != nil {
		return Credential{}, err
	}
	return Credential{
		ID: id, PrincipalID: principalID, Label: label, Provider: provider, AuthMode: authMode,
		ActiveVersion: 1, Status: "ACTIVE", SyncStatus: "SYNCED", Generation: 1,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

// ListCredentials returns metadata only.
func (s *Store) ListCredentials(principalID string) ([]Credential, error) {
	rows, err := s.db.Query(`SELECT id, principal_id, label, provider, auth_mode, active_version, status, generation, created_at, updated_at
		FROM model_provider_credentials WHERE principal_id = ? ORDER BY created_at DESC`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Credential, 0)
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.PrincipalID, &c.Label, &c.Provider, &c.AuthMode, &c.ActiveVersion, &c.Status, &c.Generation, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.SyncStatus = "SYNCED"
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) credential(principalID, id string) (Credential, error) {
	var c Credential
	err := s.db.QueryRow(`SELECT id, principal_id, label, provider, auth_mode, active_version, status, generation, created_at, updated_at
		FROM model_provider_credentials WHERE id = ? AND principal_id = ?`, id, principalID).
		Scan(&c.ID, &c.PrincipalID, &c.Label, &c.Provider, &c.AuthMode, &c.ActiveVersion, &c.Status, &c.Generation, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, err
	}
	c.SyncStatus = "SYNCED"
	return c, nil
}

// RotateCredential encrypts a new apiKey version.
func (s *Store) RotateCredential(principalID, id, apiKey string, expectedGeneration int, now int64) (Credential, error) {
	if err := validateAPIKey(apiKey); err != nil {
		return Credential{}, err
	}
	current, err := s.credential(principalID, id)
	if err != nil {
		return Credential{}, err
	}
	if current.Generation != expectedGeneration {
		return Credential{}, ErrConflict
	}
	next := current.ActiveVersion + 1
	enc, err := s.keyring.EncryptString(apiKey, secrets.Context{
		PrincipalID: principalID, EnvironmentID: credentialEnvironment, Name: current.ID, Version: next,
	})
	if err != nil {
		return Credential{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Credential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO model_provider_credential_versions
		(principal_id, credential_id, version, key_version, nonce, ciphertext, auth_tag, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		principalID, current.ID, next, enc.KeyVersion, enc.Nonce, enc.Ciphertext, enc.AuthTag, now); err != nil {
		return Credential{}, err
	}
	if _, err := tx.Exec(`UPDATE model_provider_credentials
		SET active_version = ?, generation = generation + 1, updated_at = ?
		WHERE id = ? AND principal_id = ? AND generation = ?`,
		next, now, current.ID, principalID, expectedGeneration); err != nil {
		return Credential{}, err
	}
	if err := tx.Commit(); err != nil {
		return Credential{}, err
	}
	updated, err := s.credential(principalID, id)
	if err != nil {
		return Credential{}, err
	}
	return updated, nil
}

// DeleteCredential refuses when profiles still reference it.
func (s *Store) DeleteCredential(principalID, id string, expectedGeneration int) error {
	current, err := s.credential(principalID, id)
	if err != nil {
		return err
	}
	if current.Generation != expectedGeneration {
		return ErrConflict
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM agent_model_profiles WHERE credential_id = ? AND principal_id = ?`, id, principalID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: cannot delete credential referenced by model profiles", ErrConflict)
	}
	if err := s.refuseActiveAgents(`SELECT count(*) FROM agents
		WHERE profile_id IN (SELECT r.id FROM agent_model_profile_revisions r JOIN agent_model_profiles p ON p.id = r.profile_id WHERE p.credential_id = ?)
		AND status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'LIMIT_EXCEEDED', 'INTERRUPTED')`, id); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM model_provider_credential_versions WHERE principal_id = ? AND credential_id = ?`, principalID, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM model_provider_credentials WHERE id = ? AND principal_id = ?`, id, principalID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) refuseActiveAgents(query string, args ...any) error {
	var n int
	err := s.db.QueryRow(query, args...).Scan(&n)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil
		}
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: cannot delete while active subagent leases exist", ErrConflict)
	}
	return nil
}

func resolveDownstream(apiMode string) (string, error) {
	switch apiMode {
	case "chat-completions":
		return "/v1/chat/completions", nil
	case "responses":
		return "/v1/responses", nil
	default:
		return "", fmt.Errorf("%w: unsupported apiMode", ErrInvalid)
	}
}

func resolveUpstream(provider, apiMode, customURL string) (string, error) {
	if provider == "custom" {
		if customURL == "" {
			return "", fmt.Errorf("%w: customUpstreamUrl is required for custom provider", ErrInvalid)
		}
		parsed, err := url.Parse(customURL)
		if err != nil || parsed.Scheme != "https" || (parsed.Port() != "" && parsed.Port() != "443") {
			return "", fmt.Errorf("%w: customUpstreamUrl must use HTTPS on default port 443", ErrInvalid)
		}
		return customURL, nil
	}
	downstream, err := resolveDownstream(apiMode)
	if err != nil {
		return "", err
	}
	switch provider {
	case "openai":
		return "https://api.openai.com" + downstream, nil
	case "openrouter":
		return "https://openrouter.ai/api" + downstream, nil
	case "anthropic":
		return "https://api.anthropic.com" + downstream, nil
	case "google":
		return "https://generativelanguage.googleapis.com" + downstream, nil
	default:
		return "", fmt.Errorf("%w: unsupported provider", ErrInvalid)
	}
}

func computeDigest(fields map[string]any) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]any, len(fields))
	for _, k := range keys {
		ordered[k] = fields[k]
	}
	raw, _ := json.Marshal(ordered)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateProxyOps(ops []string) ([]string, error) {
	if len(ops) < 1 || len(ops) > 10 {
		return nil, fmt.Errorf("%w: maxProxyOperations must contain 1 to 10 entries", ErrInvalid)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		if _, ok := allowedProxyOps[op]; !ok {
			return nil, fmt.Errorf("%w: unsupported proxy operation", ErrInvalid)
		}
		if _, dup := seen[op]; dup {
			continue
		}
		seen[op] = struct{}{}
		out = append(out, op)
	}
	return out, nil
}

// ProfileInput is the dashboard create/update payload. No apiKey.
type ProfileInput struct {
	ProfileID          string
	DisplayName        string
	CredentialID       string
	Model              string
	APIMode            string
	CustomUpstreamURL  string
	Pricing            Pricing
	Limits             Limits
	MaxProxyOperations []string
	ExpectedGeneration int
}

type Pricing struct {
	InputMicrosPerMillionTokens  int
	OutputMicrosPerMillionTokens int
}

type Limits struct {
	MaxInputTokens  int
	MaxOutputTokens int
	MaxCostMicros   int
}

func (s *Store) providerOf(principalID, credentialID string) (string, error) {
	var provider string
	err := s.db.QueryRow(`SELECT provider FROM model_provider_credentials WHERE id = ? AND principal_id = ?`,
		credentialID, principalID).Scan(&provider)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return provider, err
}

func insertRevision(tx *sql.Tx, rev Revision, pricing Pricing, limits Limits) error {
	raw, err := json.Marshal(rev.MaxProxyOperations)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO agent_model_profile_revisions
		(id, profile_id, principal_id, credential_id, model, api_mode, downstream_path, upstream_url,
		 input_micros_per_million, output_micros_per_million, max_input_tokens, max_output_tokens, max_cost_micros,
		 max_proxy_operations_json, digest, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rev.ID, rev.ProfileID, rev.PrincipalID, rev.CredentialID, rev.Model, rev.APIMode, rev.DownstreamPath, rev.UpstreamURL,
		pricing.InputMicrosPerMillionTokens, pricing.OutputMicrosPerMillionTokens,
		limits.MaxInputTokens, limits.MaxOutputTokens, limits.MaxCostMicros,
		string(raw), rev.Digest, rev.CreatedAt)
	return err
}

func (s *Store) buildRevision(principalID string, in ProfileInput, provider string, now int64) (Revision, error) {
	if !protocol.ValidModelProfileID(in.ProfileID) {
		return Revision{}, fmt.Errorf("%w: profileId is invalid", ErrInvalid)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixModelCredential, in.CredentialID) {
		return Revision{}, fmt.Errorf("%w: credentialId is invalid", ErrInvalid)
	}
	model := strings.TrimSpace(in.Model)
	if model == "" || len(model) > 100 {
		return Revision{}, fmt.Errorf("%w: model is invalid", ErrInvalid)
	}
	if _, ok := allowedAPIModes[in.APIMode]; !ok {
		return Revision{}, fmt.Errorf("%w: unsupported apiMode", ErrInvalid)
	}
	ops, err := validateProxyOps(in.MaxProxyOperations)
	if err != nil {
		return Revision{}, err
	}
	downstream, err := resolveDownstream(in.APIMode)
	if err != nil {
		return Revision{}, err
	}
	upstream, err := resolveUpstream(provider, in.APIMode, in.CustomUpstreamURL)
	if err != nil {
		return Revision{}, err
	}
	revID := protocol.NewOpaqueID(protocol.PrefixModelRevision)
	pricing := map[string]any{
		"inputMicrosPerMillionTokens":  in.Pricing.InputMicrosPerMillionTokens,
		"outputMicrosPerMillionTokens": in.Pricing.OutputMicrosPerMillionTokens,
	}
	limits := map[string]any{
		"maxInputTokens":  in.Limits.MaxInputTokens,
		"maxOutputTokens": in.Limits.MaxOutputTokens,
		"maxCostMicros":   in.Limits.MaxCostMicros,
	}
	digest := computeDigest(map[string]any{
		"profileId": in.ProfileID, "credentialId": in.CredentialID, "model": model, "apiMode": in.APIMode,
		"downstreamPath": downstream, "upstreamUrl": upstream, "pricing": pricing, "limits": limits,
		"maxProxyOperations": ops,
	})
	return Revision{
		ID: revID, ProfileID: in.ProfileID, PrincipalID: principalID, CredentialID: in.CredentialID,
		Model: model, APIMode: in.APIMode, DownstreamPath: downstream, UpstreamURL: upstream,
		Pricing: pricing, Limits: limits, MaxProxyOperations: ops, Digest: digest, CreatedAt: now,
	}, nil
}

// CreateProfile inserts generation 1 with an immutable first revision.
func (s *Store) CreateProfile(principalID string, in ProfileInput, now int64) (Profile, error) {
	display, err := normalizeLabel(in.DisplayName)
	if err != nil {
		return Profile{}, err
	}
	provider, err := s.providerOf(principalID, in.CredentialID)
	if err != nil {
		if err == ErrNotFound {
			return Profile{}, fmt.Errorf("%w: referenced credential was not found", ErrNotFound)
		}
		return Profile{}, err
	}
	rev, err := s.buildRevision(principalID, in, provider, now)
	if err != nil {
		return Profile{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Profile{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO agent_model_profiles
		(id, principal_id, display_name, credential_id, desired_revision_id, active_revision_id, generation, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, 'ACTIVE', ?, ?)`,
		in.ProfileID, principalID, display, in.CredentialID, rev.ID, rev.ID, now, now); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Profile{}, ErrConflict
		}
		return Profile{}, err
	}
	if err := insertRevision(tx, rev, in.Pricing, in.Limits); err != nil {
		return Profile{}, err
	}
	if err := tx.Commit(); err != nil {
		return Profile{}, err
	}
	return Profile{
		ID: in.ProfileID, PrincipalID: principalID, DisplayName: display, CredentialID: in.CredentialID,
		DesiredRevisionID: &rev.ID, ActiveRevisionID: &rev.ID, Generation: 1, Status: "ACTIVE",
		ActiveRevision: &rev, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *Store) loadRevision(id, principalID, fallbackCredential string) (*Revision, error) {
	if id == "" {
		return nil, nil
	}
	var rev Revision
	var opsJSON string
	var inMicros, outMicros, maxIn, maxOut, maxCost int
	err := s.db.QueryRow(`SELECT id, profile_id, principal_id, credential_id, model, api_mode, downstream_path, upstream_url,
		input_micros_per_million, output_micros_per_million, max_input_tokens, max_output_tokens, max_cost_micros,
		max_proxy_operations_json, digest, created_at
		FROM agent_model_profile_revisions WHERE id = ? AND principal_id = ?`, id, principalID).
		Scan(&rev.ID, &rev.ProfileID, &rev.PrincipalID, &rev.CredentialID, &rev.Model, &rev.APIMode, &rev.DownstreamPath, &rev.UpstreamURL,
			&inMicros, &outMicros, &maxIn, &maxOut, &maxCost, &opsJSON, &rev.Digest, &rev.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rev.CredentialID == "" {
		rev.CredentialID = fallbackCredential
	}
	_ = json.Unmarshal([]byte(opsJSON), &rev.MaxProxyOperations)
	if rev.MaxProxyOperations == nil {
		rev.MaxProxyOperations = []string{}
	}
	rev.Pricing = map[string]any{"inputMicrosPerMillionTokens": inMicros, "outputMicrosPerMillionTokens": outMicros}
	rev.Limits = map[string]any{"maxInputTokens": maxIn, "maxOutputTokens": maxOut, "maxCostMicros": maxCost}
	return &rev, nil
}

// ListProfiles returns profiles with the active revision attached.
func (s *Store) ListProfiles(principalID string) ([]Profile, error) {
	rows, err := s.db.Query(`SELECT id, principal_id, display_name, credential_id, desired_revision_id, active_revision_id, generation, status, created_at, updated_at
		FROM agent_model_profiles WHERE principal_id = ? ORDER BY created_at DESC`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Profile, 0)
	for rows.Next() {
		var p Profile
		var desired, active sql.NullString
		if err := rows.Scan(&p.ID, &p.PrincipalID, &p.DisplayName, &p.CredentialID, &desired, &active, &p.Generation, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		if desired.Valid {
			p.DesiredRevisionID = &desired.String
		}
		if active.Valid {
			p.ActiveRevisionID = &active.String
			rev, err := s.loadRevision(active.String, principalID, p.CredentialID)
			if err != nil {
				return nil, err
			}
			p.ActiveRevision = rev
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) profileRow(principalID, id string) (Profile, error) {
	var p Profile
	var desired, active sql.NullString
	err := s.db.QueryRow(`SELECT id, principal_id, display_name, credential_id, desired_revision_id, active_revision_id, generation, status, created_at, updated_at
		FROM agent_model_profiles WHERE id = ? AND principal_id = ?`, id, principalID).
		Scan(&p.ID, &p.PrincipalID, &p.DisplayName, &p.CredentialID, &desired, &active, &p.Generation, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, err
	}
	if desired.Valid {
		p.DesiredRevisionID = &desired.String
	}
	if active.Valid {
		p.ActiveRevisionID = &active.String
	}
	return p, nil
}

func (s *Store) getProfile(principalID, id string) (Profile, error) {
	p, err := s.profileRow(principalID, id)
	if err != nil {
		return Profile{}, err
	}
	if p.ActiveRevisionID != nil {
		rev, err := s.loadRevision(*p.ActiveRevisionID, principalID, p.CredentialID)
		if err != nil {
			return Profile{}, err
		}
		p.ActiveRevision = rev
	}
	return p, nil
}

// UpdateProfile writes a new immutable revision.
func (s *Store) UpdateProfile(principalID string, in ProfileInput, now int64) (Profile, error) {
	current, err := s.getProfile(principalID, in.ProfileID)
	if err != nil {
		return Profile{}, err
	}
	if current.Generation != in.ExpectedGeneration {
		return Profile{}, ErrConflict
	}
	display := current.DisplayName
	if strings.TrimSpace(in.DisplayName) != "" {
		display, err = normalizeLabel(in.DisplayName)
		if err != nil {
			return Profile{}, err
		}
	}
	credentialID := current.CredentialID
	if in.CredentialID != "" {
		credentialID = in.CredentialID
	}
	provider, err := s.providerOf(principalID, credentialID)
	if err != nil {
		if err == ErrNotFound {
			return Profile{}, fmt.Errorf("%w: referenced credential was not found", ErrNotFound)
		}
		return Profile{}, err
	}
	merged := in
	merged.CredentialID = credentialID
	if current.ActiveRevision != nil {
		if merged.Model == "" {
			merged.Model = current.ActiveRevision.Model
		}
		if merged.APIMode == "" {
			merged.APIMode = current.ActiveRevision.APIMode
		}
		if len(merged.MaxProxyOperations) == 0 {
			merged.MaxProxyOperations = current.ActiveRevision.MaxProxyOperations
		}
		if merged.Pricing == (Pricing{}) {
			merged.Pricing = Pricing{
				InputMicrosPerMillionTokens:  asInt(current.ActiveRevision.Pricing["inputMicrosPerMillionTokens"]),
				OutputMicrosPerMillionTokens: asInt(current.ActiveRevision.Pricing["outputMicrosPerMillionTokens"]),
			}
		}
		if merged.Limits == (Limits{}) {
			merged.Limits = Limits{
				MaxInputTokens:  asInt(current.ActiveRevision.Limits["maxInputTokens"]),
				MaxOutputTokens: asInt(current.ActiveRevision.Limits["maxOutputTokens"]),
				MaxCostMicros:   asInt(current.ActiveRevision.Limits["maxCostMicros"]),
			}
		}
	}
	if merged.APIMode == "" {
		merged.APIMode = "chat-completions"
	}
	if merged.Model == "" {
		merged.Model = "default"
	}
	if len(merged.MaxProxyOperations) == 0 {
		merged.MaxProxyOperations = []string{"files_read"}
	}
	if merged.Limits.MaxInputTokens == 0 {
		merged.Limits.MaxInputTokens = 100000
	}
	if merged.Limits.MaxOutputTokens == 0 {
		merged.Limits.MaxOutputTokens = 10000
	}
	if merged.Limits.MaxCostMicros == 0 {
		merged.Limits.MaxCostMicros = 1000000
	}
	rev, err := s.buildRevision(principalID, merged, provider, now)
	if err != nil {
		return Profile{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Profile{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertRevision(tx, rev, merged.Pricing, merged.Limits); err != nil {
		return Profile{}, err
	}
	if _, err := tx.Exec(`UPDATE agent_model_profiles
		SET display_name = ?, credential_id = ?, desired_revision_id = ?, active_revision_id = ?, generation = generation + 1, updated_at = ?
		WHERE id = ? AND principal_id = ? AND generation = ?`,
		display, credentialID, rev.ID, rev.ID, now, in.ProfileID, principalID, in.ExpectedGeneration); err != nil {
		return Profile{}, err
	}
	if err := tx.Commit(); err != nil {
		return Profile{}, err
	}
	return s.getProfile(principalID, in.ProfileID)
}

func (s *Store) setStatus(principalID, id string, expectedGeneration int, status string, now int64) (Profile, error) {
	current, err := s.profileRow(principalID, id)
	if err != nil {
		return Profile{}, err
	}
	if current.Generation != expectedGeneration {
		return Profile{}, ErrConflict
	}
	res, err := s.db.Exec(`UPDATE agent_model_profiles SET status = ?, generation = generation + 1, updated_at = ?
		WHERE id = ? AND principal_id = ? AND generation = ?`, status, now, id, principalID, expectedGeneration)
	if err != nil {
		return Profile{}, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return Profile{}, ErrConflict
	}
	return s.getProfile(principalID, id)
}

// ActivateProfile sets status ACTIVE.
func (s *Store) ActivateProfile(principalID, id string, expectedGeneration int, now int64) (Profile, error) {
	return s.setStatus(principalID, id, expectedGeneration, "ACTIVE", now)
}

// DisableProfile sets status DISABLED.
func (s *Store) DisableProfile(principalID, id string, expectedGeneration int, now int64) (Profile, error) {
	return s.setStatus(principalID, id, expectedGeneration, "DISABLED", now)
}

// DeleteProfile refuses while active subagent leases exist.
func (s *Store) DeleteProfile(principalID, id string, expectedGeneration int) error {
	current, err := s.profileRow(principalID, id)
	if err != nil {
		return err
	}
	if current.Generation != expectedGeneration {
		return ErrConflict
	}
	if err := s.refuseActiveAgents(`SELECT count(*) FROM agents
		WHERE (profile_id = ? OR profile_id IN (SELECT id FROM agent_model_profile_revisions WHERE profile_id = ?))
		AND status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'LIMIT_EXCEEDED', 'INTERRUPTED')`, id, id); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM agent_model_profile_revisions WHERE profile_id = ? AND principal_id = ?`, id, principalID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM agent_model_profiles WHERE id = ? AND principal_id = ?`, id, principalID); err != nil {
		return err
	}
	return tx.Commit()
}

// DecryptCredential returns plaintext for gateway snapshot only. Callers must not log it.
func (s *Store) DecryptCredential(principalID, id string) (string, error) {
	c, err := s.credential(principalID, id)
	if err != nil {
		return "", err
	}
	var enc secrets.Encrypted
	if err := s.db.QueryRow(`SELECT key_version, nonce, ciphertext, auth_tag FROM model_provider_credential_versions
		WHERE principal_id = ? AND credential_id = ? AND version = ?`,
		principalID, id, c.ActiveVersion).Scan(&enc.KeyVersion, &enc.Nonce, &enc.Ciphertext, &enc.AuthTag); err != nil {
		return "", err
	}
	return s.keyring.DecryptString(enc, secrets.Context{
		PrincipalID: principalID, EnvironmentID: credentialEnvironment, Name: id, Version: c.ActiveVersion,
	})
}

// StatusCounts is used by model_config_status.
func (s *Store) StatusCounts(principalID string) (activeProfiles, activeCreds int, err error) {
	if err = s.db.QueryRow(`SELECT count(*) FROM agent_model_profiles WHERE principal_id = ? AND status = 'ACTIVE'`, principalID).Scan(&activeProfiles); err != nil {
		return
	}
	err = s.db.QueryRow(`SELECT count(*) FROM model_provider_credentials WHERE principal_id = ? AND status = 'ACTIVE'`, principalID).Scan(&activeCreds)
	return
}

func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

// Now is a convenience for tests.
func Now() int64 { return time.Now().UnixMilli() }
