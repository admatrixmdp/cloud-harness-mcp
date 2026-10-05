package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestLocalBackendRejectsRemoteOnlyAndGitWithoutFlags(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := LocalBackend{Root: root}
	got := b.Call(context.Background(), protocol.OpWorkspaceOpen, json.RawMessage(`{}`))
	if got.OK || got.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("open: %+v", got)
	}
	got = b.Call(context.Background(), protocol.OpGitPush, json.RawMessage(`{}`))
	if got.OK || got.Error.Code != protocol.ErrorRepositoryOperationNotAuthorized {
		t.Fatalf("push without flag: %+v", got)
	}
	listed := b.Call(context.Background(), protocol.OpFilesList, json.RawMessage(`{"path":"."}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	moved := b.Call(context.Background(), protocol.OpFilesWriteBatch, json.RawMessage(`{"files":[{"path":"b.txt","content":"two"}]}`))
	if !moved.OK {
		t.Fatalf("batch: %+v", moved)
	}
	recovered := b.Call(context.Background(), protocol.OpWorkspaceRecover, json.RawMessage(`{"mode":"resume"}`))
	if !recovered.OK {
		t.Fatalf("recover: %+v", recovered)
	}
	statusMode := b.Call(context.Background(), protocol.OpWorkspaceRecover, json.RawMessage(`{"mode":"status"}`))
	if !statusMode.OK {
		t.Fatalf("local recover status should be wired: %+v", statusMode)
	}
	ctx := b.Call(context.Background(), protocol.OpWorkspaceContext, json.RawMessage(`{}`))
	if !ctx.OK {
		t.Fatalf("context: %+v", ctx)
	}
	dash := b.Call(context.Background(), protocol.OpGitCheckout, json.RawMessage(`{"ref":"--help"}`))
	if dash.OK || dash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash checkout: %+v", dash)
	}
	dashTree := b.Call(context.Background(), protocol.OpWorktreesCreate, json.RawMessage(`{"name":"--help","ref":"HEAD"}`))
	if dashTree.OK || dashTree.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash worktree: %+v", dashTree)
	}
	gh := b.Call(context.Background(), protocol.OpGitHubAction, json.RawMessage(`{"action":"pr_create","title":"x","head":"feat"}`))
	if gh.OK || gh.Error.Code != protocol.ErrorRepositoryOperationNotAuthorized {
		t.Fatalf("github local: %+v", gh)
	}
	secrets := b.Call(context.Background(), protocol.OpSecretsList, json.RawMessage(`{}`))
	if secrets.OK || secrets.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("secrets local: %+v", secrets)
	}
	arts := b.Call(context.Background(), protocol.OpArtifactsList, json.RawMessage(`{}`))
	if arts.OK || arts.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("artifacts local: %+v", arts)
	}
	skills := b.Call(context.Background(), protocol.OpSkillsList, json.RawMessage(`{}`))
	if !skills.OK {
		t.Fatalf("local skills list: %+v", skills)
	}
	hooks := b.Call(context.Background(), protocol.OpHooksList, json.RawMessage(`{}`))
	if !hooks.OK {
		t.Fatalf("local hooks list: %+v", hooks)
	}
	wrote := b.Call(context.Background(), protocol.OpMemoriesWrite, json.RawMessage(`{"name":"local-note","content":"stdio"}`))
	if !wrote.OK {
		t.Fatalf("local memory write: %+v", wrote)
	}
	memListed := b.Call(context.Background(), protocol.OpMemoriesList, json.RawMessage(`{}`))
	if !memListed.OK {
		t.Fatalf("local memory list: %+v", memListed)
	}
	kn := b.Call(context.Background(), protocol.OpKnowledgeList, json.RawMessage(`{}`))
	if kn.OK || kn.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("knowledge local: %+v", kn)
	}
	act := b.Call(context.Background(), protocol.OpHooksActivate, json.RawMessage(`{"manifestSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","events":["pre_commit"]}`))
	if act.OK || act.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("hooks_activate local: %+v", act)
	}
	runMissing := b.Call(context.Background(), protocol.OpHooksRun, json.RawMessage(`{"name":"lint"}`))
	if runMissing.OK || runMissing.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("hooks_run missing digest: %+v", runMissing)
	}
	skillRun := b.Call(context.Background(), protocol.OpSkillsRun, json.RawMessage(`{"name":"tdd","script":"run.sh"}`))
	if skillRun.OK || skillRun.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("skills_run missing digest: %+v", skillRun)
	}
	deploys := b.Call(context.Background(), protocol.OpDeploymentsList, json.RawMessage(`{}`))
	if !deploys.OK {
		t.Fatalf("local deployments list: %+v", deploys)
	}
}
