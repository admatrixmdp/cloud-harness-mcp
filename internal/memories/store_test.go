package memories

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestWriteReadSearchDeleteAndConflict(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "mem.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	ws := protocol.NewOpaqueID(protocol.PrefixWorkspace)
	created, err := store.Write(WriteParams{
		PrincipalID: "owner", Scope: "workspace", WorkspaceID: ws,
		Name: "alpha", Content: "first note", Tags: []string{"keep"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Generation != 1 || created.Content != "first note" {
		t.Fatalf("%+v", created)
	}
	_, err = store.Write(WriteParams{
		PrincipalID: "owner", Scope: "workspace", WorkspaceID: ws,
		Name: "alpha", Content: "dup",
	})
	if err == nil {
		t.Fatal("duplicate create must conflict")
	}
	if mem, ok := err.(*Error); !ok || mem.Code != protocol.ErrorConflict {
		t.Fatalf("dup: %v", err)
	}
	updated, err := store.Write(WriteParams{
		PrincipalID: "owner", Scope: "workspace", WorkspaceID: ws,
		Name: "alpha", Content: "second note", ExpectedGeneration: 1, Tags: []string{"keep"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Generation != 2 {
		t.Fatalf("gen %+v", updated)
	}
	stale, err := store.Write(WriteParams{
		PrincipalID: "owner", Scope: "workspace", WorkspaceID: ws,
		Name: "alpha", Content: "stale", ExpectedGeneration: 1,
	})
	if err == nil {
		t.Fatalf("stale write succeeded: %+v", stale)
	}
	got, err := store.Read(Lookup{PrincipalID: "owner", Name: "alpha", Scope: "workspace", WorkspaceID: ws})
	if err != nil || got.Content != "second note" {
		t.Fatalf("read %+v %v", got, err)
	}
	hits, _, err := store.Search(ListParams{PrincipalID: "owner", WorkspaceID: ws, Query: "second", Limit: 20})
	if err != nil || len(hits) != 1 {
		t.Fatalf("search %+v %v", hits, err)
	}
	if err := store.Delete(Lookup{PrincipalID: "owner", Name: "alpha", Scope: "workspace", WorkspaceID: ws}, 2); err != nil {
		t.Fatal(err)
	}
	_, err = store.Read(Lookup{PrincipalID: "owner", Name: "alpha", Scope: "workspace", WorkspaceID: ws})
	if err == nil {
		t.Fatal("deleted note still readable")
	}
}
