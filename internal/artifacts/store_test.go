package artifacts

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestArtifactStoreCreateListReadDeleteAndQuota(t *testing.T) {
	root := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db, Options{
		Root:               root,
		MaxArtifactBytes:   64,
		MaxPrincipalBytes:  80,
		DefaultRetentionMs: 86_400_000,
		MaxRetentionMs:     86_400_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_700_000_000_000)
	content := []byte("handoff-data-json")
	created, err := store.Create("owner", "handoff.json", content, "", "", "", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.LogicalName != "handoff.json" || created.SizeBytes != len(content) {
		t.Fatalf("%+v", created)
	}
	sum := sha256.Sum256(content)
	if created.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha %s", created.SHA256)
	}
	page, err := store.List("owner", 50, "", now)
	if err != nil || len(page.Artifacts) != 1 || page.Artifacts[0].ArtifactID != created.ArtifactID {
		t.Fatalf("list %+v %v", page, err)
	}
	chunk, err := store.Read("owner", created.ArtifactID, 0, 0, now)
	if err != nil || !chunk.EOF || chunk.BytesReturned != len(content) {
		t.Fatalf("read %+v %v", chunk, err)
	}
	if _, err := store.Read("other", created.ArtifactID, 0, 0, now); err == nil {
		t.Fatal("cross-principal")
	} else if art, ok := err.(*Error); !ok || art.Code != protocol.ErrorNotFound {
		t.Fatalf("cross-principal %v", err)
	}
	if _, err := store.Create("owner", "too-big.bin", make([]byte, 65), "", "", "", 0, now); err == nil {
		t.Fatal("per-artifact quota")
	}
	if _, err := store.Create("owner", "quota.bin", make([]byte, 64), "", "", "", 0, now); err == nil {
		t.Fatal("principal quota")
	}
	deleted, err := store.Delete("owner", created.ArtifactID, created.Generation)
	if err != nil || deleted.ArtifactID != created.ArtifactID {
		t.Fatalf("delete %+v %v", deleted, err)
	}
	if _, err := store.Read("owner", created.ArtifactID, 0, 0, now); err == nil {
		t.Fatal("read after delete")
	}
	entries, _ := os.ReadDir(filepath.Join(root, "objects"))
	if len(entries) != 0 {
		t.Fatalf("leftover objects %v", entries)
	}
}

func TestArtifactStoreRejectsEscapeAndExpired(t *testing.T) {
	root := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db, Options{Root: root, MaxArtifactBytes: 1024, MaxPrincipalBytes: 1024, DefaultRetentionMs: 1000, MaxRetentionMs: 1000})
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_700_000_000_000)
	created, err := store.Create("owner", "note.txt", []byte("abcd"), "", "", "", 1000, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("owner", created.ArtifactID, 0, 0, now.Add(2*time.Second)); err == nil {
		t.Fatal("expired must be NOT_FOUND")
	}
	if _, err := store.Create("owner", "../escape", []byte("abcd"), "", "", "", 0, now); err == nil {
		t.Fatal("logical name escape")
	}
}
