package integrations

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"

	_ "modernc.org/sqlite"
)

const secret = "ts_live_do_not_log_this_value"

func openStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "integrations.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ring, err := secrets.NewKeyring(1, []secrets.KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{11}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	store, err := Open(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestCreateEncryptsAndListNeverReturnsValue(t *testing.T) {
	store := openStore(t)
	created, err := store.Create("owner", "typesafe", "TypeSafe", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(created.PublicJSON())
	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(`"value"`)) || bytes.Contains(raw, []byte(`"principalId"`)) {
		t.Fatalf("leaked %s", raw)
	}
	var ciphertext []byte
	if err := store.db.QueryRow(`SELECT ciphertext FROM integration_credential_versions WHERE credential_id = ?`, created.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(secret)) {
		t.Fatal("plaintext in ciphertext column")
	}
	got, err := store.DecryptValue("owner", "typesafe")
	if err != nil || got != secret {
		t.Fatalf("decrypt %q %v", got, err)
	}
	other, err := store.DecryptValue("other", "typesafe")
	if err != nil || other != "" {
		t.Fatalf("scoped decrypt %q %v", other, err)
	}
	listed, err := store.List("owner")
	if err != nil || len(listed) != 1 {
		t.Fatalf("%v %#v", err, listed)
	}
	listRaw, _ := json.Marshal(listed[0].PublicJSON())
	if bytes.Contains(listRaw, []byte(secret)) {
		t.Fatalf("list leaked %s", listRaw)
	}
	if empty, err := store.List("other"); err != nil || len(empty) != 0 {
		t.Fatalf("other owner %#v", empty)
	}
}

func TestCreateConflictRotateDelete(t *testing.T) {
	store := openStore(t)
	created, err := store.Create("owner", "typesafe", "TypeSafe", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("owner", "typesafe", "again", "second", 2); err == nil {
		t.Fatal("duplicate create")
	}
	if _, err := store.Rotate("owner", created.ID, "ts_live_rotated", created.Generation+5, 3); err == nil {
		t.Fatal("stale rotate")
	}
	rotated, err := store.Rotate("owner", created.ID, "ts_live_rotated", created.Generation, 4)
	if err != nil || rotated.Generation != created.Generation+1 || rotated.ActiveVersion != 2 {
		t.Fatalf("%v %#v", err, rotated)
	}
	got, err := store.DecryptValue("owner", "typesafe")
	if err != nil || got != "ts_live_rotated" {
		t.Fatalf("rotated decrypt %q %v", got, err)
	}
	if err := store.Delete("owner", created.ID, created.Generation); err == nil {
		t.Fatal("stale delete")
	}
	if err := store.Delete("owner", created.ID, rotated.Generation); err != nil {
		t.Fatal(err)
	}
	if listed, err := store.List("owner"); err != nil || len(listed) != 0 {
		t.Fatalf("after delete %#v", listed)
	}
	if got, err := store.DecryptValue("owner", "typesafe"); err != nil || got != "" {
		t.Fatalf("deleted decrypt %q %v", got, err)
	}
}

func TestCreateRejectsEmptyValue(t *testing.T) {
	store := openStore(t)
	if _, err := store.Create("owner", "typesafe", "TypeSafe", "", 1); err == nil {
		t.Fatal("empty value")
	}
	if _, err := store.Create("owner", "openai", "OpenAI", secret, 1); err == nil {
		t.Fatal("wrong integration")
	}
	if !strings.Contains(ErrInvalid.Error(), "invalid") {
		t.Fatal(ErrInvalid)
	}
}
