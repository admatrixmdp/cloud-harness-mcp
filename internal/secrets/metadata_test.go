package secrets

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestSecretMetadataNeverStoresPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ring, err := NewKeyring(1, []KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	store, err := OpenMetadata(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	view, err := store.Create("principal-a", "env-a", "API_TOKEN", "highly-sensitive-value", "desc", now)
	if err != nil {
		t.Fatal(err)
	}
	if view.Name != "API_TOKEN" || view.ID == "" {
		t.Fatalf("%+v", view)
	}
	listed, err := store.List("principal-a", "env-a")
	if err != nil || len(listed) != 1 {
		t.Fatalf("%v %+v", err, listed)
	}
	if strings.Contains(listed[0].Name, "highly") || listed[0].Description == "highly-sensitive-value" {
		t.Fatal("list leaked plaintext")
	}
	got, err := store.Decrypt("principal-a", "env-a", "API_TOKEN")
	if err != nil || got != "highly-sensitive-value" {
		t.Fatalf("%q %v", got, err)
	}
	var blob []byte
	if err := db.QueryRow(`SELECT ciphertext FROM secret_versions`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("highly-sensitive-value")) {
		t.Fatal("plaintext stored")
	}
	if _, err := store.Decrypt("principal-a", "env-a", "API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	wrong, err := store.Decrypt("principal-b", "env-a", "API_TOKEN")
	if err == nil || wrong != "" {
		t.Fatal("cross-principal decrypt")
	}
	rotated, err := store.Rotate("principal-a", "env-a", "API_TOKEN", "rotated-secret-value", 1, nil, now.Add(time.Second))
	if err != nil || rotated.Version != 2 || rotated.Generation != 2 {
		t.Fatalf("%+v %v", rotated, err)
	}
	got, err = store.Decrypt("principal-a", "env-a", "API_TOKEN")
	if err != nil || got != "rotated-secret-value" {
		t.Fatalf("%q %v", got, err)
	}
	global, err := store.CreateGlobal("principal-a", "GLOBAL_TOKEN", "global-secret-value", 0, "", "runtime", now)
	if err != nil || global.EnvironmentID != "global" {
		t.Fatalf("%+v %v", global, err)
	}
	if strings.Contains(global.Name, "global-secret") {
		t.Fatal("name leaked value")
	}
}

func TestSecretCreateRejectsReservedNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ring, err := NewKeyring(1, []KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	store, err := OpenMetadata(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("p", "e", "PATH", "abcd", "", time.Now()); err == nil {
		t.Fatal("PATH must be reserved")
	}
	if _, err := store.Create("p", "e", "OK", "x", "", time.Now()); err == nil {
		t.Fatal("short value")
	}
}
