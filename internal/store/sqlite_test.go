package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
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
	again, ok := db.ByIdempotency("owner", "open-repo-sql-1")
	if !ok || again.ID != rec.ID {
		t.Fatal("idempotency lookup")
	}
	if _, err := db.db.Exec(`INSERT INTO workspaces (id, owner_id, idempotency_key, repository_url, status, network_profile, generation, created_at, last_activity_at, expires_at, hard_expires_at) VALUES ('ws_bbbbbbbbbbbbbbbbbbbbbb','o','k','https://github.com/x/y','ACTIVE','bridge',1,1,1,1,1)`); err == nil {
		t.Fatal("raw bridge profile must fail the CHECK constraint")
	}
	closed, ok := db.UpdateStatus(rec.ID, StatusClosed)
	if !ok || closed.Status != StatusClosed || closed.ContainerName != "" {
		t.Fatalf("close: %+v", closed)
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
