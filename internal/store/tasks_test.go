package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteDurableTaskLifecycleAndRestart(t *testing.T) {
	db, err := OpenSQLite(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	exit := 0
	rec := DurableTask{
		ID: "task_abcdefghijklmnopqrstuvwx", WorkspaceID: "ws_1", OwnerID: "owner",
		Command: "echo ok", Cwd: ".", Status: "QUEUED", IdempotencyKey: "task-key-01",
		RequestFingerprint: "aaa", BootID: "boot-a", TimeoutMs: 5000, LogPath: ".chm/tasks/t.log",
		CreatedAt: time.Now().UnixMilli(), DependsOn: []string{"task_dependencyaaaaaaaaaaaa"},
	}
	if err := db.PutTask(rec); err != nil {
		t.Fatal(err)
	}
	got, ok := db.GetTaskByKey("owner", "ws_1", "task-key-01")
	if !ok || got.ID != rec.ID || got.Status != "QUEUED" || len(got.DependsOn) != 1 {
		t.Fatalf("%+v %v", got, ok)
	}
	got.Status = "SUCCEEDED"
	got.ExitCode = &exit
	got.FinishedAt = time.Now().UnixMilli()
	if !db.UpdateTask(got) {
		t.Fatal("update")
	}
	if db.UpdateTask(got) {
		t.Fatal("stale generation must fail")
	}
	stale := DurableTask{
		ID: "task_staleaaaaaaaaaaaaaaaaaaa", WorkspaceID: "ws_1", OwnerID: "owner",
		Command: "sleep 9", Cwd: ".", Status: "RUNNING", IdempotencyKey: "task-key-stale",
		RequestFingerprint: "bbb", BootID: "boot-old", TimeoutMs: 5000, LogPath: ".chm/tasks/s.log",
		CreatedAt: time.Now().UnixMilli(), Generation: 1,
	}
	if err := db.PutTask(stale); err != nil {
		t.Fatal(err)
	}
	n := db.ReconcileStaleTasks("boot-a", time.Now().UnixMilli())
	if n != 1 {
		t.Fatalf("reconcile %d", n)
	}
	failed, ok := db.GetTask("owner", "ws_1", stale.ID)
	if !ok || failed.Status != "FAILED" || failed.ErrorCode != "RUNNER_RESTARTED" {
		t.Fatalf("%+v", failed)
	}
	if LiveStatus("SUCCEEDED") != "succeeded" || DurableStatus("queued") != "QUEUED" {
		t.Fatal("status map")
	}
}

func TestMemoryTasksGenerationFence(t *testing.T) {
	m := &MemoryTasks{}
	rec := DurableTask{ID: "task_1", OwnerID: "o", WorkspaceID: "w", Command: "echo", Status: "QUEUED", BootID: "b", LogPath: "x", Generation: 1}
	if err := m.PutTask(rec); err != nil {
		t.Fatal(err)
	}
	rec.Status = "RUNNING"
	if !m.UpdateTask(rec) {
		t.Fatal("first update")
	}
	if m.UpdateTask(rec) {
		t.Fatal("stale generation")
	}
}
