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
	ranked, _, err := store.SearchHits(ListParams{PrincipalID: "owner", WorkspaceID: ws, Query: "updated", Limit: 20})
	if err != nil || len(ranked) != 1 {
		t.Fatalf("search hits %+v %v", ranked, err)
	}
	if ranked[0].RelevancePercent <= 0 {
		t.Fatalf("relevance %+v", ranked[0])
	}
	switch ranked[0].MatchMode {
	case "hybrid", "lexical", "lexical_fallback", "semantic":
	default:
		t.Fatalf("matchMode %q", ranked[0].MatchMode)
	}
	if err := store.Delete("owner", created.ID, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("owner", created.ID); err == nil {
		t.Fatal("deleted item still readable")
	}
}

func TestHybridSearchRanksLexicalAndSemantic(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kn.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(CreateParams{
		PrincipalID: "owner", Scope: "owner", Title: "PostgreSQL Connection Pooling",
		Content: "Configure PgBouncer with transaction mode and max client connections set to 100.",
		Tags:    []string{"postgres", "database"},
	}); err != nil {
		t.Fatal(err)
	}
	item2, err := store.Create(CreateParams{
		PrincipalID: "owner", Kind: "journal", Scope: "project", ProjectID: "prj_abcdefghijklmnopqrstuv",
		Title:       "Database Latency Investigation",
		Content:     "Investigated query bottlenecks and connection timeouts on database clusters.",
		JournalType: "engineering-log", Tags: []string{"performance", "database"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(CreateParams{
		PrincipalID: "owner", Scope: "owner", Title: "Frontend State Management",
		Content: "Zustand and React context patterns for UI state synchronization.",
		Tags:    []string{"react", "frontend"},
	}); err != nil {
		t.Fatal(err)
	}
	exact, _, err := store.SearchHits(ListParams{PrincipalID: "owner", Query: "PgBouncer", Limit: 20})
	if err != nil || len(exact) == 0 {
		t.Fatalf("exact %+v %v", exact, err)
	}
	if exact[0].Item.Title != "PostgreSQL Connection Pooling" || exact[0].RelevancePercent <= 0 {
		t.Fatalf("exact hit %+v", exact[0])
	}
	semantic, _, err := store.SearchHits(ListParams{PrincipalID: "owner", Query: "connection timeouts on database clusters", Limit: 20})
	if err != nil || len(semantic) == 0 {
		t.Fatalf("semantic %+v %v", semantic, err)
	}
	if semantic[0].Item.ID != item2.ID {
		t.Fatalf("semantic top %+v", semantic[0].Item)
	}
	filtered, _, err := store.SearchHits(ListParams{PrincipalID: "owner", Query: "database", ProjectID: "prj_abcdefghijklmnopqrstuv", Limit: 20})
	if err != nil || len(filtered) != 1 || filtered[0].Item.ID != item2.ID {
		t.Fatalf("project filter %+v %v", filtered, err)
	}
	foreign, _, err := store.SearchHits(ListParams{PrincipalID: "other", Query: "database", Limit: 20})
	if err != nil || len(foreign) != 0 {
		t.Fatalf("isolation %+v %v", foreign, err)
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
