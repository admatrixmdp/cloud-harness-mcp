package grants

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestCreateApproveConsumeOnce(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "grants.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	cmd := SkillGrantCommand("tdd", "run.sh", "aa")
	first, err := store.Create("owner", "ws_1", cmd, ".", 60_000)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create("owner", "ws_1", cmd, ".", 60_000)
	if err != nil || second.ID != first.ID {
		t.Fatalf("pending reuse %+v %v", second, err)
	}
	if store.Consume("owner", "ws_1", first.ID, first.CommandSHA256, ".") {
		t.Fatal("pending grant must not consume")
	}
	if !store.Approve("owner", first.ID) {
		t.Fatal("approve")
	}
	if !store.Consume("owner", "ws_1", first.ID, first.CommandSHA256, ".") {
		t.Fatal("consume")
	}
	if store.Consume("owner", "ws_1", first.ID, first.CommandSHA256, ".") {
		t.Fatal("consumed twice")
	}
	got := ApprovalRequired(first, "tdd", "run.sh")
	if got.OK || got.Error.Code != protocol.ErrorPrivilegeApprovalRequired {
		t.Fatalf("%+v", got)
	}
}
