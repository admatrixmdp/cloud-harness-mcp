package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPIKeyCreateVerifyRevokeDoesNotStorePlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0)
	rec, plaintext, err := db.CreateAPIKey("principal-1", "laptop", 30, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DisplayPrefix == plaintext || strings.Contains(rec.DisplayPrefix, strings.Split(plaintext, ".")[1]) {
		t.Fatal("display prefix leaked secret")
	}
	if !strings.HasPrefix(plaintext, "chm_key_") {
		t.Fatalf("plaintext %s", plaintext)
	}
	id, ok := db.VerifyAPIKey(plaintext, now.Add(time.Minute))
	if !ok || id != rec.ID {
		t.Fatalf("verify %s %v", id, ok)
	}
	if _, ok := db.VerifyAPIKey("chm_key_apk_abcdefghijklmnopqrstuvwx."+strings.Repeat("A", 43), now); ok {
		t.Fatal("wrong secret accepted")
	}
	if _, ok := db.RevokeAPIKey("principal-1", rec.ID, rec.Generation, now.Add(time.Hour)); !ok {
		t.Fatal("revoke")
	}
	if _, ok := db.VerifyAPIKey(plaintext, now.Add(2*time.Hour)); ok {
		t.Fatal("revoked key still verified")
	}
}

func TestAPIKeyRejectsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0)
	_, plaintext, err := db.CreateAPIKey("p", "k", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := db.VerifyAPIKey(plaintext, now.Add(48*time.Hour)); ok {
		t.Fatal("expired key accepted")
	}
}
