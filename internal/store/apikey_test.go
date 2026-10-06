package store

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
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

func TestAPIKeyListOmitsSecretAndMarksExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0)
	rec, plaintext, err := db.CreateAPIKey("principal-1", "laptop", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := db.ListAPIKeys("principal-1", now)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list %v %v", listed, err)
	}
	raw, _ := json.Marshal(listed[0].PublicJSON())
	if strings.Contains(string(raw), plaintext) || strings.Contains(string(raw), strings.Split(plaintext, ".")[1]) {
		t.Fatalf("list leaked secret %s", raw)
	}
	if listed[0].ID != rec.ID || listed[0].State != protocol.APIKeyActive {
		t.Fatalf("list %+v", listed[0])
	}
	expired, err := db.ListAPIKeys("principal-1", now.Add(48*time.Hour))
	if err != nil || expired[0].State != protocol.APIKeyExpired {
		t.Fatalf("expired %+v %v", expired, err)
	}
}
