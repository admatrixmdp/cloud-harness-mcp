package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestSQLiteRoundTripAndRejectsBridge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	rec := Record{
		ID:             "ws_abcdefghijklmnopqrstuvwx",
		OwnerID:        "owner",
		IdempotencyKey: "open-repo-sql-1",
		RepositoryURL:  "https://github.com/bestagentkits/cloud-harness-mcp",
		Status:         StatusActive,
		NetworkProfile: protocol.NetworkNone,
		Generation:     1,
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(5 * time.Minute),
		HardExpiresAt:  now.Add(15 * time.Minute),
	}
	if err := db.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, ok := db.Get(rec.ID)
	if !ok || got.Status != StatusActive || got.NetworkProfile != protocol.NetworkNone {
		t.Fatalf("%+v", got)
	}
	if got.EnvironmentID != "" {
		t.Fatalf("empty env leaked %q", got.EnvironmentID)
	}
	again, ok := db.ByIdempotency("owner", "open-repo-sql-1")
	if !ok || again.ID != rec.ID {
		t.Fatal("idempotency lookup")
	}
	if _, err := db.db.Exec(`INSERT INTO workspaces (id, owner_id, idempotency_key, repository_url, workspace_path, status, network_profile, generation, created_at, last_activity_at, expires_at, hard_expires_at) VALUES ('ws_bbbbbbbbbbbbbbbbbbbbbb','o','k','https://github.com/x/y','/job','ACTIVE','bridge',1,1,1,1,1)`); err == nil {
		t.Fatal("raw bridge profile must fail the CHECK constraint")
	}
	closed, ok := db.UpdateStatus(rec.ID, StatusClosed)
	if !ok || closed.Status != StatusClosed || closed.ContainerName != "" {
		t.Fatalf("close: %+v", closed)
	}
}

func TestSQLiteClaimForReapingFencesGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	rec := Record{
		ID:             "ws_dddddddddddddddddddddddd",
		OwnerID:        "owner",
		IdempotencyKey: "open-reap-sql-1",
		RepositoryURL:  "https://github.com/bestagentkits/cloud-harness-mcp",
		Status:         StatusActive,
		NetworkProfile: protocol.NetworkNone,
		Generation:     3,
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(5 * time.Minute),
		HardExpiresAt:  now.Add(15 * time.Minute),
	}
	if err := db.Put(rec); err != nil {
		t.Fatal(err)
	}
	if db.ClaimForReaping(rec.ID, 2, true) {
		t.Fatal("stale generation must fail")
	}
	if !db.ClaimForReaping(rec.ID, 3, true) {
		t.Fatal("matching generation must claim")
	}
	got, ok := db.Get(rec.ID)
	if !ok || got.Status != StatusReaping || got.Generation != 4 {
		t.Fatalf("%+v", got)
	}
	if db.ClaimForReaping(rec.ID, 4, true) {
		t.Fatal("REAPING must not be claimed again")
	}
}

func TestSQLiteOwnerStateAndActivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	rec := Record{
		ID:             "ws_cccccccccccccccccccccccc",
		OwnerID:        "owner",
		IdempotencyKey: "open-recover-sql-1",
		RepositoryURL:  "https://github.com/bestagentkits/cloud-harness-mcp",
		Status:         StatusExpiredRecoverable,
		NetworkProfile: protocol.NetworkNone,
		Generation:     1,
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(-time.Minute),
		HardExpiresAt:  now.Add(15 * time.Minute),
	}
	if err := db.Put(rec); err != nil {
		t.Fatal(err)
	}
	activated, ok := db.Activate(rec.ID, now.Add(time.Minute), now)
	if !ok || activated.Status != StatusActive {
		t.Fatalf("activate: %+v", activated)
	}
	db.SetPreferredWorkspace("owner", rec.ID)
	pref, ok := db.PreferredWorkspace("owner")
	if !ok || pref != rec.ID {
		t.Fatalf("preferred %q", pref)
	}
	db.SetGitIdentity("owner", "Agent", "agent@example.com")
	name, email, ok := db.GitIdentity("owner")
	if !ok || name != "Agent" || email != "agent@example.com" {
		t.Fatalf("%s %s", name, email)
	}
}

func TestSQLitePutsOntoTypeScriptV12Schema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ts-v12.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  repository_url TEXT NOT NULL,
  repository_ref TEXT,
  container_name TEXT,
  workspace_path TEXT NOT NULL,
  environment_id TEXT,
  status TEXT NOT NULL,
  network_profile TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  hard_expires_at INTEGER,
  git_author_name TEXT,
  git_author_email TEXT,
  mutation_locked_until INTEGER,
  mutation_lock_count INTEGER NOT NULL DEFAULT 0,
  generation INTEGER NOT NULL DEFAULT 1,
  error TEXT,
  request_fingerprint TEXT
);
CREATE UNIQUE INDEX workspaces_owner_idempotency ON workspaces(owner_id, idempotency_key);
`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	rec := Record{
		ID:             "ws_ffffffffffffffffffffffff",
		OwnerID:        "prn_owner",
		IdempotencyKey: "open-ts-v12-1",
		RepositoryURL:  "https://github.com/admatrixorg/goso",
		Status:         StatusCreating,
		NetworkProfile: protocol.NetworkNone,
		Fingerprint:    "fp-v12",
		WorkspacePath:  "/var/lib/cloud-harness/jobs/ws_ffffffffffffffffffffffff",
		Generation:     1,
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(time.Minute),
		HardExpiresAt:  now.Add(2 * time.Minute),
	}
	if err := db.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, ok := db.Get(rec.ID)
	if !ok || got.Fingerprint != "fp-v12" || got.WorkspacePath != rec.WorkspacePath {
		t.Fatalf("%+v", got)
	}
	listed := db.List("prn_owner")
	if len(listed) != 1 || listed[0].ID != rec.ID {
		t.Fatalf("list %+v", listed)
	}
}

func TestSQLitePersistsEnvironmentIDAndMigratesLegacySchema(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "state.db")
	fresh, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	envID := "env_abcdefghijklmnopqrstuvwx"
	rec := Record{
		ID:             "ws_dddddddddddddddddddddddd",
		OwnerID:        "owner",
		IdempotencyKey: "open-env-sql-1",
		RepositoryURL:  "https://github.com/bestagentkits/cloud-harness-mcp",
		Status:         StatusActive,
		NetworkProfile: protocol.NetworkNone,
		EnvironmentID:  envID,
		Generation:     1,
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(5 * time.Minute),
		HardExpiresAt:  now.Add(15 * time.Minute),
	}
	if err := fresh.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, ok := fresh.Get(rec.ID)
	_ = fresh.Close()
	if !ok || got.EnvironmentID != envID {
		t.Fatalf("round-trip %+v", got)
	}

	legacy := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  repository_url TEXT NOT NULL,
  repository_ref TEXT,
  container_name TEXT,
  status TEXT NOT NULL,
  network_profile TEXT NOT NULL CHECK(network_profile IN ('network-none','dependency-access')),
  request_fingerprint TEXT,
  generation INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  hard_expires_at INTEGER NOT NULL
);
INSERT INTO workspaces (id, owner_id, idempotency_key, repository_url, status, network_profile, generation, created_at, last_activity_at, expires_at, hard_expires_at)
VALUES ('ws_eeeeeeeeeeeeeeeeeeeeeeee','owner','open-legacy-1','https://github.com/bestagentkits/cloud-harness-mcp','ACTIVE','network-none',1,1,1,2,3);
`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	migrated, err := OpenSQLite(legacy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	legacyRec, ok := migrated.Get("ws_eeeeeeeeeeeeeeeeeeeeeeee")
	if !ok {
		t.Fatal("legacy row missing after migrate")
	}
	if legacyRec.EnvironmentID != "" {
		t.Fatalf("legacy env %q", legacyRec.EnvironmentID)
	}
	legacyRec.EnvironmentID = envID
	if err := migrated.Put(legacyRec); err != nil {
		t.Fatal(err)
	}
	again, ok := migrated.Get(legacyRec.ID)
	if !ok || again.EnvironmentID != envID {
		t.Fatalf("migrated put %+v", again)
	}
}

func TestSQLiteInstanceNetworkDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.db")
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, ok := db.DefaultNetworkProfile(); ok {
		t.Fatal("unset default")
	}
	none := protocol.NetworkNone
	db.SetDefaultNetworkProfile(&none, time.Now())
	got, ok := db.DefaultNetworkProfile()
	if !ok || got != protocol.NetworkNone {
		t.Fatalf("%v %v", got, ok)
	}
	reopened, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	again, ok := reopened.DefaultNetworkProfile()
	if !ok || again != protocol.NetworkNone {
		t.Fatalf("persist %v %v", again, ok)
	}
	reopened.SetDefaultNetworkProfile(nil, time.Now())
	if _, ok := reopened.DefaultNetworkProfile(); ok {
		t.Fatal("cleared default")
	}
}
