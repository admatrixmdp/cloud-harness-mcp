package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteGitOpReplayAndFingerprintConflict(t *testing.T) {
	db, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rec := GitOpRecord{
		OwnerID: "owner", WorkspaceID: "ws_1", IdempotencyKey: "finalize-key-01",
		Operation: GitOpFinalize, RequestFingerprint: "aaa", CreatedAt: time.Now().UTC(),
	}
	action, _ := db.AcquireGitOp(rec)
	if action != GitOpAcquired {
		t.Fatalf("acquire %s", action)
	}
	if !db.FinishGitOp("owner", "ws_1", "finalize-key-01", GitOpSucceeded, `{"message":"ok","data":{"commitSha":"abc"}}`, "", "abc") {
		t.Fatal("finish")
	}
	replay, existing := db.AcquireGitOp(rec)
	if replay != GitOpReplaySucceeded || existing.LocalCommitSHA != "abc" {
		t.Fatalf("replay %s %+v", replay, existing)
	}
	other := rec
	other.RequestFingerprint = "bbb"
	conflict, _ := db.AcquireGitOp(other)
	if conflict != GitOpFingerprintConflict {
		t.Fatalf("conflict %s", conflict)
	}
}

func TestMemoryGitOpInFlight(t *testing.T) {
	m := &MemoryGitOps{}
	rec := GitOpRecord{OwnerID: "o", WorkspaceID: "w", IdempotencyKey: "k", Operation: GitOpFinalize, RequestFingerprint: "fp"}
	if action, _ := m.AcquireGitOp(rec); action != GitOpAcquired {
		t.Fatalf("%s", action)
	}
	if action, _ := m.AcquireGitOp(rec); action != GitOpInFlight {
		t.Fatalf("%s", action)
	}
}
