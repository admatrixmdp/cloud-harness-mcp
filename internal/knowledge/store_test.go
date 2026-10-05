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

func TestLinkUnlinkAndBoundedGraph(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kn.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Create(CreateParams{PrincipalID: "owner", Scope: "owner", Title: "A", Content: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.Create(CreateParams{PrincipalID: "owner", Scope: "owner", Title: "B", Content: "beta"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateLink("owner", a.ID, a.ID, "relates-to", "manual")
	if err == nil {
		t.Fatal("self-link must fail")
	}
	link, err := store.CreateLink("owner", a.ID, b.ID, "supports", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if !linkIDRe.MatchString(link.ID) || link.Relation != "supports" {
		t.Fatalf("%+v", link)
	}
	nodes, edges, truncated, err := store.Graph(GraphParams{PrincipalID: "owner", RootID: a.ID, Depth: 1, MaxNodes: 50})
	if err != nil || truncated {
		t.Fatalf("graph %v truncated=%v", err, truncated)
	}
	if len(nodes) != 2 || len(edges) != 1 {
		t.Fatalf("nodes=%d edges=%d", len(nodes), len(edges))
	}
	ok, err := store.DeleteLink("owner", link.ID, "", "", "")
	if err != nil || !ok {
		t.Fatalf("unlink %v %v", ok, err)
	}
	nodes, edges, _, err = store.Graph(GraphParams{PrincipalID: "owner", RootID: a.ID, Depth: 1, MaxNodes: 50})
	if err != nil || len(nodes) != 1 || len(edges) != 0 {
		t.Fatalf("after unlink nodes=%d edges=%d err=%v", len(nodes), len(edges), err)
	}
}
