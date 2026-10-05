package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestSafePathRejectsEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := SafePath(root, "../outside", false); err == nil {
		t.Fatal(".. must be rejected")
	}
	if _, err := SafePath(root, "/etc/passwd", false); err == nil {
		t.Fatal("absolute path must be rejected")
	}
	if _, err := SafePath(root, "foo\x00bar", true); err == nil {
		t.Fatal("null byte must be rejected")
	}
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := SafePath(root, "ok.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "ok.txt" {
		t.Fatalf("got %s", got)
	}
}

func TestSafePathSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := SafePath(root, "link/secret", false); err == nil {
		t.Fatal("symlink escape must be rejected")
	}
}

func TestFilesReadWriteRoundTrip(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	written := ws.Execute(context.Background(), protocol.OpFilesWrite, json.RawMessage(`{"path":"src/a.txt","content":"hello"}`))
	if !written.OK {
		t.Fatalf("%+v", written)
	}
	read := ws.Execute(context.Background(), protocol.OpFilesRead, json.RawMessage(`{"path":"src/a.txt"}`))
	if !read.OK {
		t.Fatalf("%+v", read)
	}
	data, _ := read.Data.(map[string]any)
	if data["content"] != "hello" {
		t.Fatalf("%v", data)
	}
	listed := ws.Execute(context.Background(), protocol.OpFilesList, json.RawMessage(`{"path":"src"}`))
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}
}

func TestFilesReadTruncates(t *testing.T) {
	root := t.TempDir()
	body := bytes.Repeat([]byte("a"), 100)
	if err := os.WriteFile(filepath.Join(root, "big.txt"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	ws := Workspace{Root: root}
	got := ws.Execute(context.Background(), protocol.OpFilesRead, json.RawMessage(`{"path":"big.txt","limit":16}`))
	if !got.OK || !got.Truncated {
		t.Fatalf("%+v", got)
	}
	data, _ := got.Data.(map[string]any)
	if data["content"] != strings.Repeat("a", 16) {
		t.Fatalf("content %v", data["content"])
	}
	if got.Cursor == "" {
		t.Fatal("expected cursor")
	}
}

func TestTruncateHelper(t *testing.T) {
	out, truncated := Truncate([]byte("abcdef"), 3)
	if !truncated || string(out) != "abc" {
		t.Fatalf("%q %v", out, truncated)
	}
	out, truncated = Truncate([]byte("ab"), 3)
	if truncated || string(out) != "ab" {
		t.Fatalf("%q %v", out, truncated)
	}
}

func TestExecRunConfinedAndTruncated(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	escaped := ws.Execute(context.Background(), protocol.OpExecRun, json.RawMessage(`{"cwd":"../","command":"pwd"}`))
	if escaped.OK {
		t.Fatal("cwd escape must fail")
	}
	got := ws.Execute(context.Background(), protocol.OpExecRun, json.RawMessage(`{"command":"printf '%s' xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","maxOutputBytes":8}`))
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	if !got.Truncated {
		t.Fatalf("expected truncation: %+v", got)
	}
}

func TestHandleStdinJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HARNESS_WORKSPACE_ROOT", root)
	if err := os.WriteFile(filepath.Join(root, "n.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := bytes.NewReader([]byte(`{"operation":"files_read","input":{"path":"n.txt"}}`))
	var out bytes.Buffer
	if err := HandleStdin(in, &out); err != nil {
		t.Fatal(err)
	}
	var result protocol.ToolResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("%+v", result)
	}
}

func TestApplyPatchUniqueAndConflict(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("one two one"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := Workspace{Root: root}
	dup := ws.Execute(context.Background(), protocol.OpFilesApplyPatch, json.RawMessage(`{"path":"a.txt","oldText":"one","newText":"ONE"}`))
	if dup.OK || dup.Error.Code != protocol.ErrorConflict {
		t.Fatalf("duplicate oldText: %+v", dup)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("alpha beta"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok := ws.Execute(context.Background(), protocol.OpFilesApplyPatch, json.RawMessage(`{"path":"b.txt","oldText":"beta","newText":"gamma"}`))
	if !ok.OK {
		t.Fatalf("%+v", ok)
	}
	body, _ := os.ReadFile(filepath.Join(root, "b.txt"))
	if string(body) != "alpha gamma" {
		t.Fatalf("%q", body)
	}
}

func TestGrepStaysInsideWorkspace(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hit.txt"), []byte("find-me-here"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("find-me-here"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}
	ws := Workspace{Root: root}
	escaped := ws.Execute(context.Background(), protocol.OpGrepSearch, json.RawMessage(`{"path":"../","pattern":"find-me-here"}`))
	if escaped.OK {
		t.Fatal("path escape must fail")
	}
	got := ws.Execute(context.Background(), protocol.OpGrepSearch, json.RawMessage(`{"pattern":"find-me-here"}`))
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	data, _ := got.Data.(map[string]any)
	matches, _ := data["matches"].([]string)
	joined := strings.Join(matches, "\n")
	if strings.Contains(joined, "secret.txt") {
		t.Fatalf("leaked outside match: %s", joined)
	}
	if !strings.Contains(joined, "hit.txt") {
		t.Fatalf("missing in-workspace match: %s", joined)
	}
}

func TestUnsupportedOperation(t *testing.T) {
	ws := Workspace{Root: t.TempDir()}
	got := ws.Execute(context.Background(), protocol.OpAgentSpawn, nil)
	if got.OK || got.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("%+v", got)
	}
}

func TestWriteBatchAndMoveStayConfined(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	escaped := ws.Execute(context.Background(), protocol.OpFilesWriteBatch, json.RawMessage(`{"files":[{"path":"../x.txt","content":"no"}]}`))
	if escaped.OK {
		t.Fatal("batch escape must fail")
	}
	conflict := ws.Execute(context.Background(), protocol.OpFilesWriteBatch, json.RawMessage(`{"files":[{"path":"dir","content":"a"},{"path":"dir/nested.txt","content":"b"}]}`))
	if conflict.OK || conflict.Error.Code != protocol.ErrorConflict {
		t.Fatalf("ancestor conflict: %+v", conflict)
	}
	ok := ws.Execute(context.Background(), protocol.OpFilesWriteBatch, json.RawMessage(`{"files":[{"path":"a.txt","content":"one"},{"path":"b.txt","content":"two"}]}`))
	if !ok.OK {
		t.Fatalf("%+v", ok)
	}
	moved := ws.Execute(context.Background(), protocol.OpFilesMove, json.RawMessage(`{"source":"a.txt","destination":"nested/c.txt"}`))
	if !moved.OK {
		t.Fatalf("%+v", moved)
	}
	if _, err := os.Stat(filepath.Join(root, "a.txt")); !os.IsNotExist(err) {
		t.Fatal("source should be gone")
	}
	body, err := os.ReadFile(filepath.Join(root, "nested/c.txt"))
	if err != nil || string(body) != "one" {
		t.Fatalf("%q %v", body, err)
	}
	out := ws.Execute(context.Background(), protocol.OpFilesMove, json.RawMessage(`{"source":"nested/c.txt","destination":"../escape.txt"}`))
	if out.OK {
		t.Fatal("move escape must fail")
	}
}

func TestSymbolsStayInsideWorkspace(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "FindMe.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := Workspace{Root: root}
	got := ws.Execute(context.Background(), protocol.OpSymbolsSearch, json.RawMessage(`{"query":"findme"}`))
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	escaped := ws.Execute(context.Background(), protocol.OpSymbolsSearch, json.RawMessage(`{"query":"x","path":"../"}`))
	if escaped.OK {
		t.Fatal("symbols path escape must fail")
	}
}

func TestGitLocalBranchAddCommitRejectsDashArgs(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	init := ws.gitCmd(context.Background(), "init", "init")
	if !init.OK || exitOf(init) != 0 {
		t.Fatalf("init: %+v", init)
	}
	cfg := ws.gitCmd(context.Background(), "cfg", "-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "--allow-empty", "-m", "seed")
	if !cfg.OK {
		t.Fatalf("seed: %+v", cfg)
	}
	rejected := ws.Execute(context.Background(), protocol.OpGitCheckout, json.RawMessage(`{"ref":"--help"}`))
	if rejected.OK || rejected.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash ref: %+v", rejected)
	}
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	added := ws.Execute(context.Background(), protocol.OpGitAdd, json.RawMessage(`{"all":true}`))
	if !added.OK {
		t.Fatalf("add: %+v", added)
	}
	committed := ws.Execute(context.Background(), protocol.OpGitCommit, json.RawMessage(`{"message":"test: note","authorName":"Harness Test","authorEmail":"harness@example.invalid"}`))
	if !committed.OK {
		t.Fatalf("commit: %+v", committed)
	}
	created := ws.Execute(context.Background(), protocol.OpGitBranch, json.RawMessage(`{"action":"create","name":"feature"}`))
	if !created.OK {
		t.Fatalf("branch: %+v", created)
	}
}
