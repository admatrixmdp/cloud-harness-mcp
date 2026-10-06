package audit

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestAuditListCursorAndIsolation(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Record("owner", "workspace_open", "workspace", "ws_1", 1, map[string]any{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Record("owner", "workspace_close", "workspace", "ws_1", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Record("other", "secret_create", "secret", "sec_1", 1, nil); err != nil {
		t.Fatal(err)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixAudit, first.ID) || !protocol.ValidOpaqueID(protocol.PrefixAudit, second.ID) {
		t.Fatalf("ids %s %s", first.ID, second.ID)
	}
	page, err := store.List("owner", "", 1)
	if err != nil || len(page) != 1 || page[0].ID != second.ID {
		t.Fatalf("page %+v err %v", page, err)
	}
	next, err := store.List("owner", page[0].ID, 10)
	if err != nil || len(next) != 1 || next[0].ID != first.ID {
		t.Fatalf("next %+v err %v", next, err)
	}
	other, err := store.List("other", "", 10)
	if err != nil || len(other) != 1 || other[0].Action != "secret_create" {
		t.Fatalf("other %+v err %v", other, err)
	}
	empty, err := store.List("owner", "aud_"+string(make([]byte, 24)), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("invalid cursor leaked %v", empty)
	}
}
