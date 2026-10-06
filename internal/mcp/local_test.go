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
	b := NewLocalBackend(root, false, false)
	got := b.Call(context.Background(), protocol.OpWorkspaceOpen, json.RawMessage(`{}`))
	if got.OK || got.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("open: %+v", got)
	}
	finalize := b.Call(context.Background(), protocol.OpWorkspaceFinalize, json.RawMessage(`{"commitMessage":"x"}`))
	if finalize.OK || finalize.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("finalize local: %+v", finalize)
	}
	got = b.Call(context.Background(), protocol.OpGitPush, json.RawMessage(`{}`))
	if got.OK || got.Error.Code != protocol.ErrorRepositoryOperationNotAuthorized {
		t.Fatalf("push without flag: %+v", got)
	}
	fetchOff := b.Call(context.Background(), protocol.OpGitFetch, json.RawMessage(`{}`))
	if fetchOff.OK || fetchOff.Error.Code != protocol.ErrorForbidden {
		t.Fatalf("fetch without flag: %+v", fetchOff)
	}
	netOnly := NewLocalBackend(root, true, false)
	pushNetOnly := netOnly.Call(context.Background(), protocol.OpGitPush, json.RawMessage(`{}`))
	if pushNetOnly.OK || pushNetOnly.Error.Code != protocol.ErrorRepositoryOperationNotAuthorized {
		t.Fatalf("push with network only: %+v", pushNetOnly)
	}
	enabled := NewLocalBackend(root, true, true)
	badRemote := enabled.Call(context.Background(), protocol.OpGitFetch, json.RawMessage(`{"remote":"upstream"}`))
	if badRemote.OK || badRemote.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("enabled fetch validation: %+v", badRemote)
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
	suggest := b.Call(context.Background(), protocol.OpSkillSuggest, json.RawMessage(`{"prompt":"hello"}`))
	if !suggest.OK {
		t.Fatalf("local skill_suggest: %+v", suggest)
	}
	if suggest.Data.(map[string]any)["outboundCalls"] != 0 {
		t.Fatalf("local suggest egress %+v", suggest.Data)
	}
	sessions := b.Call(context.Background(), protocol.OpSessionsList, json.RawMessage(`{}`))
	if !sessions.OK {
		t.Fatalf("local sessions list: %+v", sessions)
	}
	shell := b.Call(context.Background(), protocol.OpShellOpen, json.RawMessage(`{"cwd":".","idempotencyKey":"local-shell-01"}`))
	if !shell.OK {
		t.Fatalf("local shell open: %+v", shell)
	}
	shellID, _ := shell.Data.(map[string]any)["id"].(string)
	closed := b.Call(context.Background(), protocol.OpShellClose, json.RawMessage(`{"shellId":"`+shellID+`"}`))
	if !closed.OK {
		t.Fatalf("local shell close: %+v", closed)
	}
	taskListed := b.Call(context.Background(), protocol.OpTasksList, json.RawMessage(`{}`))
	if !taskListed.OK {
		t.Fatalf("local tasks list: %+v", taskListed)
	}
	missingOp := b.Call(context.Background(), protocol.OpOperationStatus, json.RawMessage(`{"operationId":"op_ffffffffffffffffffffffff"}`))
	if missingOp.OK || missingOp.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("local missing operation: %+v", missingOp)
	}
	agent := b.Call(context.Background(), protocol.OpAgentSpawn, json.RawMessage(`{"prompt":"x","idempotencyKey":"local-agent-01","profileId":"coding-fast","proxyOperations":["files_list"]}`))
	if agent.OK || agent.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("local agent spawn: %+v", agent)
	}
}

func TestLocalBackendWorkspaceLifecycleAndIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sentinel.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := NewLocalBackend(root, true, true)
	listed := b.Call(context.Background(), protocol.OpWorkspaceList, json.RawMessage(`{}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	data, _ := listed.Data.(map[string]any)
	workspaces, _ := data["workspaces"].([]any)
	if len(workspaces) != 1 {
		t.Fatalf("listed workspaces: %+v", listed.Data)
	}
	rec, _ := workspaces[0].(map[string]any)
	id, _ := rec["workspaceId"].(string)
	if id == "" || rec["status"] != "ACTIVE" || rec["networkProfile"] != "local-host" {
		t.Fatalf("public record: %+v", rec)
	}
	actions, _ := rec["availableActions"].([]string)
	if !containsString(actions, "workspace_lease_renew") || !containsString(actions, "workspace_recover") {
		t.Fatalf("actions: %+v", rec["availableActions"])
	}

	status := b.Call(context.Background(), protocol.OpWorkspaceStatus, json.RawMessage(`{"workspaceId":"`+id+`"}`))
	if !status.OK {
		t.Fatalf("status: %+v", status)
	}
	statusData, _ := status.Data.(map[string]any)
	caps, _ := statusData["capabilities"].(map[string]any)
	if caps["mode"] != "local" || caps["gitNetwork"] != true {
		t.Fatalf("status caps: %+v", caps)
	}

	capRes := b.Call(context.Background(), protocol.OpWorkspaceCapabilities, json.RawMessage(`{}`))
	if !capRes.OK {
		t.Fatalf("capabilities: %+v", capRes)
	}
	capData, _ := capRes.Data.(map[string]any)
	ops, _ := capData["operations"].(map[string]any)
	if ops["gitFetch"] != true || ops["gitPush"] != true || ops["execRun"] != true {
		t.Fatalf("operations: %+v", ops)
	}
	repoCaps, _ := capData["capabilities"].(map[string]any)["repository"].(map[string]any)
	if repoCaps["push"] != true || repoCaps["issuesRead"] != false {
		t.Fatalf("repository caps: %+v", repoCaps)
	}

	wrong := b.Call(context.Background(), protocol.OpWorkspaceStatus, json.RawMessage(`{"workspaceId":"ws_ffffffffffffffffffffffff"}`))
	if wrong.OK || wrong.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("wrong id: %+v", wrong)
	}

	renew := b.Call(context.Background(), protocol.OpWorkspaceLeaseRenew, json.RawMessage(`{"workspaceId":"`+id+`"}`))
	if !renew.OK || renew.Message != "Local workspace lease is permanent" {
		t.Fatalf("renew: %+v", renew)
	}

	identity := b.Call(context.Background(), protocol.OpGitIdentityStatus, json.RawMessage(`{}`))
	if !identity.OK {
		t.Fatalf("identity status: %+v", identity)
	}
	identData, _ := identity.Data.(map[string]any)
	if identData["name"] != "Cloud Harness Agent" || identData["source"] != "default" {
		t.Fatalf("default identity: %+v", identData)
	}
	set := b.Call(context.Background(), protocol.OpGitIdentitySet, json.RawMessage(`{"name":"Alice Developer","email":"alice@example.com"}`))
	if !set.OK {
		t.Fatalf("identity set: %+v", set)
	}
	after := b.Call(context.Background(), protocol.OpGitIdentityStatus, json.RawMessage(`{}`))
	afterData, _ := after.Data.(map[string]any)
	if afterData["name"] != "Alice Developer" || afterData["email"] != "alice@example.com" || afterData["source"] != "owner" {
		t.Fatalf("set identity: %+v", after.Data)
	}
	ctx := b.Call(context.Background(), protocol.OpWorkspaceContext, json.RawMessage(`{}`))
	ctxData, _ := ctx.Data.(map[string]any)
	gitIdent, _ := ctxData["gitIdentity"].(map[string]any)
	if gitIdent["email"] != "alice@example.com" || ctxData["branch"] != "HEAD" {
		t.Fatalf("context identity: %+v", ctx.Data)
	}

	closeRes := b.Call(context.Background(), protocol.OpWorkspaceClose, json.RawMessage(`{"workspaceId":"`+id+`"}`))
	if !closeRes.OK {
		t.Fatalf("close: %+v", closeRes)
	}
	got, err := os.ReadFile(filepath.Join(root, "sentinel.txt"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("close must not delete host files: %s %v", got, err)
	}
	afterList := b.Call(context.Background(), protocol.OpWorkspaceList, json.RawMessage(`{}`))
	afterListData, _ := afterList.Data.(map[string]any)
	afterWorkspaces, _ := afterListData["workspaces"].([]any)
	if len(afterWorkspaces) != 0 {
		t.Fatalf("list after close: %+v", afterList.Data)
	}
	statusAfter := b.Call(context.Background(), protocol.OpWorkspaceStatus, json.RawMessage(`{"workspaceId":"`+id+`"}`))
	if statusAfter.OK || statusAfter.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("status after close: %+v", statusAfter)
	}
	renewClosed := b.Call(context.Background(), protocol.OpWorkspaceLeaseRenew, json.RawMessage(`{"workspaceId":"`+id+`"}`))
	if renewClosed.OK || renewClosed.Error.Code != protocol.ErrorExpired {
		t.Fatalf("renew after close: %+v", renewClosed)
	}
	recoverClosed := b.Call(context.Background(), protocol.OpWorkspaceRecover, json.RawMessage(`{"workspaceId":"`+id+`"}`))
	if recoverClosed.OK || recoverClosed.Error.Code != protocol.ErrorExpired {
		t.Fatalf("recover after close: %+v", recoverClosed)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
