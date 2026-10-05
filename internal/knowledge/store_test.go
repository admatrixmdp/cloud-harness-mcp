package knowledge

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestCreateReadUpdateSearchDelete(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kn.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	ws := protocol.NewOpaqueID(protocol.PrefixWorkspace)
	created, err := store.Create(CreateParams{
		PrincipalID: "owner", Kind: "memory", Scope: "workspace", WorkspaceID: ws,
		Title: "Alpha note", Content: "keep this knowledge", Tags: []string{"keep"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Generation != 1 || !itemIDRe.MatchString(created.ID) {
		t.Fatalf("%+v", created)
	}
	_, err = store.Create(CreateParams{
		PrincipalID: "owner", Kind: "memory", Scope: "workspace", WorkspaceID: ws,
		Title: "Alpha note", Content: "dup",
	})
	if err == nil {
		t.Fatal("duplicate title must conflict")
	}
	got, err := store.Read("owner", created.ID)
	if err != nil || got.Content != "keep this knowledge" {
		t.Fatalf("read %+v %v", got, err)
	}
	title := "Alpha note"
	content := "updated knowledge"
	updated, err := store.Update(UpdateParams{
		PrincipalID: "owner", ID: created.ID, ExpectedGeneration: 1, Title: &title, Content: &content,
	})
	if err != nil || updated.Generation != 2 {
		t.Fatalf("update %+v %v", updated, err)
	}
	hits, _, err := store.Search(ListParams{PrincipalID: "owner", WorkspaceID: ws, Query: "updated", Limit: 20})
	if err != nil || len(hits) != 1 {
		t.Fatalf("search %+v %v", hits, err)
	}
	if err := store.Delete("owner", created.ID, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("owner", created.ID); err == nil {
		t.Fatal("deleted item still readable")
	}
}

func TestJournalRequiresType(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kn.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.Create(CreateParams{
		PrincipalID: "owner", Kind: "journal", Scope: "owner", Title: "Decision", Content: "ship it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.JournalType != "engineering-log" || item.OccurredAt == 0 {
		t.Fatalf("%+v", item)
	}
}
