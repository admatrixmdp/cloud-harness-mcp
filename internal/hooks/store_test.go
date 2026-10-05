package hooks

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestActivateDeactivateAndRejectBadDigest(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "hooks.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, err = store.Activate("owner", "ws_1", "--help", sha, 0)
	if err == nil {
		t.Fatal("dash event must fail")
	}
	_, err = store.Activate("owner", "ws_1", "pre_commit", "not-a-digest", 0)
	if err == nil {
		t.Fatal("short digest must fail")
	}
	act, err := store.Activate("owner", "ws_1", "pre_commit", sha, 120)
	if err != nil {
		t.Fatal(err)
	}
	if act.Event != "pre_commit" || act.ManifestSHA256 != sha {
		t.Fatalf("%+v", act)
	}
	listed, err := store.Active("owner", "ws_1")
	if err != nil || len(listed) != 1 {
		t.Fatalf("active %+v %v", listed, err)
	}
	ok, err := store.Deactivate("owner", "ws_1", "pre_commit")
	if err != nil || !ok {
		t.Fatalf("deactivate %v %v", ok, err)
	}
	listed, err = store.Active("owner", "ws_1")
	if err != nil || len(listed) != 0 {
		t.Fatalf("after deactivate %+v %v", listed, err)
	}
}
