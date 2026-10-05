package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	rebase := ws.Execute(context.Background(), protocol.OpGitRebase, json.RawMessage(`{"action":"start","upstream":"--onto"}`))
	if rebase.OK || rebase.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash rebase: %+v", rebase)
	}
	if err := os.WriteFile(filepath.Join(root, "dirty.txt"), []byte("dirty"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := ws.Execute(context.Background(), protocol.OpWorkspaceRecover, json.RawMessage(`{"mode":"status"}`))
	if !status.OK {
		t.Fatalf("recover status: %+v", status)
	}
	if status.Data.(map[string]any)["hasUncommitted"] != true {
		t.Fatalf("expected uncommitted: %+v", status.Data)
	}
	patch := ws.Execute(context.Background(), protocol.OpWorkspaceRecover, json.RawMessage(`{"mode":"patch"}`))
	if !patch.OK {
		t.Fatalf("recover patch: %+v", patch)
	}
	if _, ok := patch.Data.(map[string]any)["workingTreePatch"]; !ok {
		t.Fatalf("missing patch: %+v", patch.Data)
	}
	bad := ws.Execute(context.Background(), protocol.OpWorkspaceRecover, json.RawMessage(`{"mode":"export"}`))
	if bad.OK || bad.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("worker export: %+v", bad)
	}
}

func TestWorktreesStayConfinedAndRejectDashNames(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	if got := ws.gitCmd(context.Background(), "init", "init"); !got.OK || exitOf(got) != 0 {
		t.Fatalf("init: %+v", got)
	}
	if got := ws.gitCmdEnv(context.Background(), []string{"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com"}, "seed", "commit", "--allow-empty", "-m", "seed"); !got.OK || exitOf(got) != 0 {
		t.Fatalf("seed: %+v", got)
	}
	dash := ws.Execute(context.Background(), protocol.OpWorktreesCreate, json.RawMessage(`{"name":"--help","ref":"HEAD"}`))
	if dash.OK || dash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash name: %+v", dash)
	}
	slash := ws.Execute(context.Background(), protocol.OpWorktreesCreate, json.RawMessage(`{"name":"../escape","ref":"HEAD"}`))
	if slash.OK || slash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("slash name: %+v", slash)
	}
	dashRef := ws.Execute(context.Background(), protocol.OpWorktreesCreate, json.RawMessage(`{"name":"verification-tree","ref":"--help"}`))
	if dashRef.OK || dashRef.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash ref: %+v", dashRef)
	}
	created := ws.Execute(context.Background(), protocol.OpWorktreesCreate, json.RawMessage(`{"name":"verification-tree","ref":"HEAD"}`))
	if !created.OK {
		t.Fatalf("create: %+v", created)
	}
	listed := ws.Execute(context.Background(), protocol.OpWorktreesList, json.RawMessage(`{}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	out, _ := listed.Data.(map[string]any)["output"].(string)
	if !strings.Contains(out, ".worktrees/verification-tree") {
		t.Fatalf("list missing tree: %s", out)
	}
	info, err := os.Stat(filepath.Join(root, ".worktrees", "verification-tree"))
	if err != nil || !info.IsDir() {
		t.Fatalf("worktree dir: %v", err)
	}
	removed := ws.Execute(context.Background(), protocol.OpWorktreesRemove, json.RawMessage(`{"name":"verification-tree","force":true}`))
	if !removed.OK {
		t.Fatalf("remove: %+v", removed)
	}
	if _, err := os.Stat(filepath.Join(root, ".worktrees", "verification-tree")); !os.IsNotExist(err) {
		t.Fatalf("worktree still present: %v", err)
	}
}

func TestSkillsListReadOverlayAndConfine(t *testing.T) {
	root := t.TempDir()
	builtin := t.TempDir()
	t.Setenv("BUILTIN_SKILLS_ROOT", builtin)
	t.Setenv("CH_OWNER_SKILLS_ROOT", t.TempDir())
	writeSkill := func(dir, name, body string) {
		skillDir := filepath.Join(dir, name)
		if err := os.MkdirAll(skillDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSkill(builtin, "alpha", "---\ndescription: builtin alpha\n---\nbuilt-in body")
	writeSkill(filepath.Join(root, ".agents", "skills"), "alpha", "repo alpha")
	writeSkill(filepath.Join(root, ".agents", "skills"), "beta", "repo beta")
	ws := Workspace{Root: root}
	listed := ws.Execute(context.Background(), protocol.OpSkillsList, json.RawMessage(`{}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	listedSkills := asMaps(listed.Data.(map[string]any)["skills"])
	if len(listedSkills) != 2 {
		t.Fatalf("want 2 skills, got %+v", listed.Data)
	}
	var alpha map[string]any
	for _, m := range listedSkills {
		if m["name"] == "alpha" {
			alpha = m
		}
	}
	if alpha["source"] != "built-in" {
		t.Fatalf("overlay %+v", alpha)
	}
	if len(asMaps(alpha["shadowed"])) != 1 {
		t.Fatalf("shadowed %+v", alpha["shadowed"])
	}
	read := ws.Execute(context.Background(), protocol.OpSkillsRead, json.RawMessage(`{"name":"alpha"}`))
	if !read.OK {
		t.Fatalf("read: %+v", read)
	}
	if !strings.Contains(read.Data.(map[string]any)["content"].(string), "built-in body") {
		t.Fatalf("read content %+v", read.Data)
	}
	repoRead := ws.Execute(context.Background(), protocol.OpSkillsRead, json.RawMessage(`{"name":"alpha","source":"repository"}`))
	if !repoRead.OK {
		t.Fatalf("repo read: %+v", repoRead)
	}
	if repoRead.Data.(map[string]any)["content"] != "repo alpha" {
		t.Fatalf("repo content %+v", repoRead.Data)
	}
	missing := ws.Execute(context.Background(), protocol.OpSkillsRead, json.RawMessage(`{"name":"nope"}`))
	if missing.OK || missing.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("missing: %+v", missing)
	}
	badName := ws.Execute(context.Background(), protocol.OpSkillsRead, json.RawMessage(`{"name":"../escape"}`))
	if badName.OK || badName.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("bad name: %+v", badName)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.md"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	escapeDir := filepath.Join(root, ".agents", "skills", "escape")
	if err := os.MkdirAll(escapeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(escapeDir, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	escaped := ws.Execute(context.Background(), protocol.OpSkillsList, json.RawMessage(`{}`))
	if !escaped.OK {
		t.Fatalf("list with escape: %+v", escaped)
	}
	for _, item := range asMaps(escaped.Data.(map[string]any)["skills"]) {
		if item["name"] == "escape" {
			t.Fatal("symlink-escaping skill must not be listed")
		}
	}
}

func TestHooksListConfinedAndFiltersEvents(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	empty := ws.Execute(context.Background(), protocol.OpHooksList, json.RawMessage(`{}`))
	if !empty.OK {
		t.Fatalf("empty: %+v", empty)
	}
	if empty.Data.(map[string]any)["manifestSha256"] != nil {
		t.Fatalf("missing manifest should be null: %+v", empty.Data)
	}
	if len(asMaps(empty.Data.(map[string]any)["hooks"])) != 0 {
		t.Fatalf("want no hooks: %+v", empty.Data)
	}
	if err := os.MkdirAll(filepath.Join(root, ".cloud-harness"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{
  "version": 1,
  "hooks": [
    {"name":"lint","events":["pre_commit"],"failurePolicy":"block","order":10},
    {"name":"--help","events":["manual"]},
    {"name":"notify","event":"post_commit","failurePolicy":"warn","order":20}
  ]
}`
	if err := os.WriteFile(filepath.Join(root, ".cloud-harness", "hooks.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	listed := ws.Execute(context.Background(), protocol.OpHooksList, json.RawMessage(`{}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	hooks := asMaps(listed.Data.(map[string]any)["hooks"])
	if len(hooks) != 2 {
		t.Fatalf("dash name must be skipped: %+v", listed.Data)
	}
	if hooks[0]["name"] != "lint" || hooks[0]["failurePolicy"] != "block" {
		t.Fatalf("lint %+v", hooks[0])
	}
	filtered := ws.Execute(context.Background(), protocol.OpHooksList, json.RawMessage(`{"event":"pre_commit"}`))
	if !filtered.OK {
		t.Fatalf("filter: %+v", filtered)
	}
	page := asMaps(filtered.Data.(map[string]any)["hooks"])
	if len(page) != 1 || page[0]["name"] != "lint" {
		t.Fatalf("pre_commit %+v", filtered.Data)
	}
	bad := ws.Execute(context.Background(), protocol.OpHooksList, json.RawMessage(`{"event":"--help"}`))
	if bad.OK || bad.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash event: %+v", bad)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "hooks.json"), []byte(`{"hooks":[{"name":"escape","events":["manual"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".cloud-harness", "hooks.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "hooks.json"), filepath.Join(root, ".cloud-harness", "hooks.json")); err != nil {
		t.Fatal(err)
	}
	escaped := ws.Execute(context.Background(), protocol.OpHooksList, json.RawMessage(`{}`))
	if escaped.OK {
		t.Fatalf("symlink escape must fail: %+v", escaped)
	}
	if escaped.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("escape code: %+v", escaped)
	}
}

func TestMemoriesStayConfinedAndRejectDashNames(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	empty := ws.Execute(context.Background(), protocol.OpMemoriesList, json.RawMessage(`{}`))
	if !empty.OK {
		t.Fatalf("empty: %+v", empty)
	}
	dash := ws.Execute(context.Background(), protocol.OpMemoriesWrite, json.RawMessage(`{"name":"--help","content":"nope"}`))
	if dash.OK || dash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash name: %+v", dash)
	}
	slash := ws.Execute(context.Background(), protocol.OpMemoriesWrite, json.RawMessage(`{"name":"../escape","content":"nope"}`))
	if slash.OK || slash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("slash name: %+v", slash)
	}
	wrote := ws.Execute(context.Background(), protocol.OpMemoriesWrite, json.RawMessage(`{"name":"note","content":"hello memory"}`))
	if !wrote.OK {
		t.Fatalf("write: %+v", wrote)
	}
	if _, err := os.Stat(filepath.Join(root, ".cloud-harness", "memories", "note.md")); err != nil {
		t.Fatal(err)
	}
	read := ws.Execute(context.Background(), protocol.OpMemoriesRead, json.RawMessage(`{"name":"note"}`))
	if !read.OK || read.Data.(map[string]any)["content"] != "hello memory" {
		t.Fatalf("read: %+v", read)
	}
	found := ws.Execute(context.Background(), protocol.OpMemoriesSearch, json.RawMessage(`{"query":"hello"}`))
	if !found.OK {
		t.Fatalf("search: %+v", found)
	}
	if len(asMaps(found.Data.(map[string]any)["memories"])) != 1 {
		t.Fatalf("search hits %+v", found.Data)
	}
	deleted := ws.Execute(context.Background(), protocol.OpMemoriesDelete, json.RawMessage(`{"name":"note"}`))
	if !deleted.OK {
		t.Fatalf("delete: %+v", deleted)
	}
	missing := ws.Execute(context.Background(), protocol.OpMemoriesRead, json.RawMessage(`{"name":"note"}`))
	if missing.OK || missing.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("missing: %+v", missing)
	}
}

func TestHooksRunRequiresDigestAndRejectsMismatch(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".cloud-harness"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"version":1,"hooks":[{"name":"lint","events":["pre_commit"],"argv":["/bin/echo","hook-ok"],"failurePolicy":"block"}]}`)
	if err := os.WriteFile(filepath.Join(root, ".cloud-harness", "hooks.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	ws := Workspace{Root: root}
	listed := ws.Execute(context.Background(), protocol.OpHooksList, json.RawMessage(`{}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	sha, _ := listed.Data.(map[string]any)["manifestSha256"].(string)
	if sha == "" {
		t.Fatalf("missing digest %+v", listed.Data)
	}
	missing := ws.Execute(context.Background(), protocol.OpHooksRun, json.RawMessage(`{"name":"lint"}`))
	if missing.OK || missing.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("missing digest: %+v", missing)
	}
	mismatch := ws.Execute(context.Background(), protocol.OpHooksRun, json.RawMessage(`{"name":"lint","expectedManifestSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	if mismatch.OK || mismatch.Error.Code != protocol.ErrorConflict {
		t.Fatalf("mismatch: %+v", mismatch)
	}
	ok := ws.Execute(context.Background(), protocol.OpHooksRun, json.RawMessage(`{"name":"lint","expectedManifestSha256":"`+sha+`"}`))
	if !ok.OK {
		t.Fatalf("run: %+v", ok)
	}
	if !strings.Contains(ok.Data.(map[string]any)["output"].(string), "hook-ok") {
		t.Fatalf("output %+v", ok.Data)
	}
	if err := os.WriteFile(filepath.Join(root, ".cloud-harness", "hooks.json"), []byte(`{"version":1,"hooks":[{"name":"lint","events":["pre_commit"],"argv":["/bin/echo","tampered"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := ws.Execute(context.Background(), protocol.OpHooksRun, json.RawMessage(`{"name":"lint","expectedManifestSha256":"`+sha+`"}`))
	if stale.OK || stale.Error.Code != protocol.ErrorConflict {
		t.Fatalf("stale: %+v", stale)
	}
}

func TestSkillsRunRequiresDigestAndRejectsMismatch(t *testing.T) {
	root := t.TempDir()
	skillDir := filepath.Join(root, ".cloud-harness", "skills", "tdd")
	if err := os.MkdirAll(filepath.Join(skillDir, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# TDD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := []byte("#!/bin/sh\necho skill-ok\n")
	if err := os.WriteFile(filepath.Join(skillDir, "scripts", "run.sh"), script, 0o700); err != nil {
		t.Fatal(err)
	}
	ws := Workspace{Root: root}
	missing := ws.Execute(context.Background(), protocol.OpSkillsRun, json.RawMessage(`{"name":"tdd","script":"run.sh"}`))
	if missing.OK || missing.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("missing digest: %+v", missing)
	}
	mismatch := ws.Execute(context.Background(), protocol.OpSkillsRun, json.RawMessage(`{"name":"tdd","script":"run.sh","expectedSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	if mismatch.OK || mismatch.Error.Code != protocol.ErrorConflict {
		t.Fatalf("mismatch: %+v", mismatch)
	}
	sum := sha256.Sum256(script)
	sha := hex.EncodeToString(sum[:])
	ok := ws.Execute(context.Background(), protocol.OpSkillsRun, json.RawMessage(`{"name":"tdd","script":"run.sh","expectedSha256":"`+sha+`"}`))
	if !ok.OK {
		t.Fatalf("run: %+v", ok)
	}
	if !strings.Contains(ok.Data.(map[string]any)["output"].(string), "skill-ok") {
		t.Fatalf("output %+v", ok.Data)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "scripts", "run.sh"), []byte("#!/bin/sh\necho tampered\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := ws.Execute(context.Background(), protocol.OpSkillsRun, json.RawMessage(`{"name":"tdd","script":"run.sh","expectedSha256":"`+sha+`"}`))
	if stale.OK || stale.Error.Code != protocol.ErrorConflict {
		t.Fatalf("stale: %+v", stale)
	}
}

func TestSkillSuggestIsLexicalAndNeverEchosPrompt(t *testing.T) {
	root := t.TempDir()
	skillDir := filepath.Join(root, ".cloud-harness", "skills", "tdd")
	if err := os.MkdirAll(skillDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# TDD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := Workspace{Root: root}
	empty := (Workspace{Root: t.TempDir()}).Execute(context.Background(), protocol.OpSkillSuggest, json.RawMessage(`{"prompt":"please help"}`))
	if !empty.OK {
		t.Fatalf("empty: %+v", empty)
	}
	if empty.Data.(map[string]any)["reason"] != "empty_roster" || empty.Data.(map[string]any)["outboundCalls"] != 0 {
		t.Fatalf("empty data %+v", empty.Data)
	}
	over := ws.Execute(context.Background(), protocol.OpSkillSuggest, json.RawMessage(`{"prompt":"`+strings.Repeat("x", 8193)+`"}`))
	if over.OK || over.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("oversize: %+v", over)
	}
	secret := "please use tdd on secret-token-xyz"
	got := ws.Execute(context.Background(), protocol.OpSkillSuggest, json.RawMessage(`{"prompt":"`+secret+`"}`))
	if !got.OK {
		t.Fatalf("suggest: %+v", got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "secret-token-xyz") {
		t.Fatalf("prompt leaked: %s", raw)
	}
	suggested, _ := got.Data.(map[string]any)["suggested"].(map[string]any)
	if suggested["name"] != "tdd" {
		t.Fatalf("suggested %+v", got.Data)
	}
	if got.Data.(map[string]any)["outboundCalls"] != 0 {
		t.Fatalf("egress %+v", got.Data)
	}
}

func TestDeploymentsListOmitsCommandAndRunConflicts(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".cloud-harness"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".cloud-harness", "deployments.json"), []byte(`{"preview":"echo deploy-ok","broken":{"command":"exit 7","cwd":"."}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := Workspace{Root: root}
	listed := ws.Execute(context.Background(), protocol.OpDeploymentsList, json.RawMessage(`{}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	rows := asMaps(listed.Data.(map[string]any)["deployments"])
	if len(rows) != 2 {
		t.Fatalf("rows %+v", listed.Data)
	}
	for _, row := range rows {
		if _, ok := row["command"]; ok {
			t.Fatalf("command leaked %+v", row)
		}
		if row["cwd"] != "." {
			t.Fatalf("cwd %+v", row)
		}
	}
	ok := ws.Execute(context.Background(), protocol.OpDeploymentsRun, json.RawMessage(`{"name":"preview"}`))
	if !ok.OK {
		t.Fatalf("preview: %+v", ok)
	}
	if !strings.Contains(ok.Data.(map[string]any)["output"].(string), "deploy-ok") {
		t.Fatalf("output %+v", ok.Data)
	}
	failed := ws.Execute(context.Background(), protocol.OpDeploymentsRun, json.RawMessage(`{"name":"broken"}`))
	if failed.OK || failed.Error.Code != protocol.ErrorConflict {
		t.Fatalf("broken: %+v", failed)
	}
	if failed.Data.(map[string]any)["exitCode"] != 7 {
		t.Fatalf("exit %+v", failed.Data)
	}
	dash := ws.Execute(context.Background(), protocol.OpDeploymentsRun, json.RawMessage(`{"name":"--help"}`))
	if dash.OK || dash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash: %+v", dash)
	}
}

func TestSessionsOpenIOCloseAndIdempotency(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	dash := ws.Execute(context.Background(), protocol.OpSessionsOpen, json.RawMessage(`{"name":"--help","idempotencyKey":"session-key-01"}`))
	if dash.OK || dash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash: %+v", dash)
	}
	open := ws.Execute(context.Background(), protocol.OpSessionsOpen, json.RawMessage(`{"name":"review","cwd":".","idempotencyKey":"session-key-01"}`))
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id, _ := open.Data.(map[string]any)["id"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixSession, id) {
		t.Fatalf("id %q", id)
	}
	replay := ws.Execute(context.Background(), protocol.OpSessionsOpen, json.RawMessage(`{"name":"review","cwd":".","idempotencyKey":"session-key-01"}`))
	if !replay.OK || replay.Data.(map[string]any)["id"] != id {
		t.Fatalf("replay: %+v", replay)
	}
	conflict := ws.Execute(context.Background(), protocol.OpSessionsOpen, json.RawMessage(`{"name":"review","cwd":".","idempotencyKey":"session-key-02"}`))
	if conflict.OK || conflict.Error.Code != protocol.ErrorConflict {
		t.Fatalf("conflict: %+v", conflict)
	}
	io := ws.Execute(context.Background(), protocol.OpSessionsIO, json.RawMessage(`{"sessionId":"`+id+`","input":"echo session-ok\n","waitMs":300}`))
	if !io.OK {
		t.Fatalf("io: %+v", io)
	}
	if !strings.Contains(io.Data.(map[string]any)["output"].(string), "session-ok") {
		t.Fatalf("output %+v", io.Data)
	}
	listed := ws.Execute(context.Background(), protocol.OpSessionsList, json.RawMessage(`{}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	rows := asMaps(listed.Data.(map[string]any)["sessions"])
	if len(rows) != 1 || rows[0]["id"] != id {
		t.Fatalf("list rows %+v", listed.Data)
	}
	if _, ok := rows[0]["output"]; ok {
		t.Fatalf("list leaked output %+v", rows[0])
	}
	closed := ws.Execute(context.Background(), protocol.OpSessionsClose, json.RawMessage(`{"sessionId":"`+id+`"}`))
	if !closed.OK {
		t.Fatalf("close: %+v", closed)
	}
	if closed.Data.(map[string]any)["status"] != "cancelled" {
		t.Fatalf("status %+v", closed.Data)
	}
}

func TestShellOpenIOCloseAndIdempotency(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	missing := ws.Execute(context.Background(), protocol.OpShellOpen, json.RawMessage(`{"cwd":"."}`))
	if missing.OK || missing.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("missing key: %+v", missing)
	}
	open := ws.Execute(context.Background(), protocol.OpShellOpen, json.RawMessage(`{"cwd":".","idempotencyKey":"shell-key-01"}`))
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id, _ := open.Data.(map[string]any)["id"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixShell, id) {
		t.Fatalf("id %q", id)
	}
	if _, ok := open.Data.(map[string]any)["name"]; ok {
		t.Fatalf("shell should not carry a name %+v", open.Data)
	}
	replay := ws.Execute(context.Background(), protocol.OpShellOpen, json.RawMessage(`{"cwd":".","idempotencyKey":"shell-key-01"}`))
	if !replay.OK || replay.Data.(map[string]any)["id"] != id {
		t.Fatalf("replay: %+v", replay)
	}
	io := ws.Execute(context.Background(), protocol.OpShellIO, json.RawMessage(`{"shellId":"`+id+`","input":"echo shell-ok\n","waitMs":300}`))
	if !io.OK {
		t.Fatalf("io: %+v", io)
	}
	if !strings.Contains(io.Data.(map[string]any)["output"].(string), "shell-ok") {
		t.Fatalf("output %+v", io.Data)
	}
	future := ws.Execute(context.Background(), protocol.OpShellIO, json.RawMessage(`{"shellId":"`+id+`","cursor":"999999999","waitMs":0}`))
	if future.OK || future.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("future cursor: %+v", future)
	}
	closed := ws.Execute(context.Background(), protocol.OpShellClose, json.RawMessage(`{"shellId":"`+id+`"}`))
	if !closed.OK {
		t.Fatalf("close: %+v", closed)
	}
	if closed.Data.(map[string]any)["status"] != "cancelled" {
		t.Fatalf("status %+v", closed.Data)
	}
}

func waitTask(t *testing.T, ws Workspace, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := ws.Execute(context.Background(), protocol.OpTasksStatus, json.RawMessage(`{"taskId":"`+id+`"}`))
		if !st.OK {
			t.Fatalf("status: %+v", st)
		}
		data := st.Data.(map[string]any)
		switch data["status"] {
		case "queued", "running":
			time.Sleep(20 * time.Millisecond)
			continue
		default:
			return data
		}
	}
	t.Fatal("task did not settle")
	return nil
}

func TestTasksRunStatusCancelGraphAndIdempotency(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	missing := ws.Execute(context.Background(), protocol.OpTasksRun, json.RawMessage(`{"command":"echo x"}`))
	if missing.OK || missing.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("missing key: %+v", missing)
	}
	run := ws.Execute(context.Background(), protocol.OpTasksRun, json.RawMessage(`{"command":"echo task-ok","cwd":".","idempotencyKey":"task-key-01","timeoutMs":5000}`))
	if !run.OK {
		t.Fatalf("run: %+v", run)
	}
	id, _ := run.Data.(map[string]any)["id"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		t.Fatalf("id %q", id)
	}
	replay := ws.Execute(context.Background(), protocol.OpTasksRun, json.RawMessage(`{"command":"echo task-ok","cwd":".","idempotencyKey":"task-key-01","timeoutMs":5000}`))
	if !replay.OK || replay.Data.(map[string]any)["id"] != id {
		t.Fatalf("replay: %+v", replay)
	}
	conflict := ws.Execute(context.Background(), protocol.OpTasksRun, json.RawMessage(`{"command":"echo other","cwd":".","idempotencyKey":"task-key-01","timeoutMs":5000}`))
	if conflict.OK || conflict.Error.Code != protocol.ErrorConflict {
		t.Fatalf("conflict: %+v", conflict)
	}
	data := waitTask(t, ws, id)
	if data["status"] != "succeeded" || !strings.Contains(data["output"].(string), "task-ok") {
		t.Fatalf("settled %+v", data)
	}
	dep := ws.Execute(context.Background(), protocol.OpTasksRun, json.RawMessage(`{"command":"echo dependent-ok","cwd":".","idempotencyKey":"task-key-02","timeoutMs":5000,"dependsOn":["`+id+`"]}`))
	if !dep.OK {
		t.Fatalf("dep: %+v", dep)
	}
	depID := dep.Data.(map[string]any)["id"].(string)
	depData := waitTask(t, ws, depID)
	if depData["status"] != "succeeded" || !strings.Contains(depData["output"].(string), "dependent-ok") {
		t.Fatalf("dep settled %+v", depData)
	}
	graph := ws.Execute(context.Background(), protocol.OpTasksGraph, json.RawMessage(`{}`))
	if !graph.OK {
		t.Fatalf("graph: %+v", graph)
	}
	edges := asMaps(graph.Data.(map[string]any)["edges"])
	found := false
	for _, e := range edges {
		if e["from"] == id && e["to"] == depID {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing edge %+v", graph.Data)
	}
	listed := ws.Execute(context.Background(), protocol.OpTasksList, json.RawMessage(`{}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	for _, row := range asMaps(listed.Data.(map[string]any)["tasks"]) {
		if _, ok := row["output"]; ok {
			t.Fatalf("list leaked output %+v", row)
		}
	}
	cancellable := ws.Execute(context.Background(), protocol.OpTasksRun, json.RawMessage(`{"command":"sleep 3; echo leaked","cwd":".","idempotencyKey":"task-key-03","timeoutMs":10000}`))
	if !cancellable.OK {
		t.Fatalf("cancellable: %+v", cancellable)
	}
	cid := cancellable.Data.(map[string]any)["id"].(string)
	cancelled := ws.Execute(context.Background(), protocol.OpTasksCancel, json.RawMessage(`{"taskId":"`+cid+`"}`))
	if !cancelled.OK || cancelled.Data.(map[string]any)["status"] != "cancelled" {
		t.Fatalf("cancel: %+v", cancelled)
	}
}

func asMaps(raw any) []map[string]any {
	switch v := raw.(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}
