package githubapp

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "github.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestSetupStateConsumeOnce(t *testing.T) {
	store := openStore(t)
	state, _, err := store.CreateSetup("owner", "1", "", 60_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(state) < 32 {
		t.Fatalf("state %q", state)
	}
	got, err := store.ConsumeSetup(state, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpectedAppID != "1" {
		t.Fatalf("%+v", got)
	}
	if _, err := store.ConsumeSetup(state, "owner"); err != ErrInvalidSetup {
		t.Fatalf("reuse %v", err)
	}
	if _, err := store.ConsumeSetup(state, "other"); err != ErrInvalidSetup {
		t.Fatalf("foreign %v", err)
	}
}

func TestReplaceVerifiedProjectsWithoutOwner(t *testing.T) {
	store := openStore(t)
	rec, err := store.ReplaceVerified("owner", Verified{
		AppID: "1", InstallationID: "101", AccountID: "201", AccountLogin: "org-one",
		Status:       "active",
		Repositories: []VerifiedRepo{{Owner: "Org-One", Repository: "Repo1", Contents: "write"}},
	}, 100)
	if err != nil {
		t.Fatal(err)
	}
	pub := rec.PublicJSON()
	if _, ok := pub["ownerId"]; ok {
		t.Fatal("ownerId leaked")
	}
	if pub["installationId"] != "101" || pub["accountLogin"] != "org-one" {
		t.Fatalf("%v", pub)
	}
	grants, err := store.ListRepositoryGrants("owner", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Owner != "org-one" || grants[0].Repository != "repo1" {
		t.Fatalf("%+v", grants)
	}
	if _, ok := grants[0].PublicJSON()["secretToken"]; ok {
		t.Fatal("secretToken leaked")
	}
	foreign, err := store.ListInstallations("other")
	if err != nil || len(foreign) != 0 {
		t.Fatalf("isolation %+v %v", foreign, err)
	}
}

func TestReplaceVerifiedConflictAndDisconnect(t *testing.T) {
	store := openStore(t)
	if _, err := store.ReplaceVerified("owner-a", Verified{
		AppID: "1", InstallationID: "101", AccountID: "201", AccountLogin: "org-a", Status: "active",
	}, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReplaceVerified("owner-b", Verified{
		AppID: "1", InstallationID: "101", AccountID: "202", AccountLogin: "org-b", Status: "active",
	}, 110); err != ErrConflict {
		t.Fatalf("conflict %v", err)
	}
	rec, ok, err := store.RemoveInstallation("owner-a", "101", 120)
	if err != nil || !ok || rec.InstallationID != "101" {
		t.Fatalf("remove %+v %v %v", rec, ok, err)
	}
	listed, err := store.ListInstallations("owner-a")
	if err != nil || len(listed) != 0 {
		t.Fatalf("listed %+v %v", listed, err)
	}
}
