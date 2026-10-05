package runner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

type recordingEngine struct {
	created []string
	removed []string
}

func (e *recordingEngine) Create(_ context.Context, rec store.Record) (string, error) {
	id := rec.ID
	if len(id) < 19 {
		id = id + "xxxxxxxxxxxxxxxxxxx"
	}
	name := "cloud-harness-ws-" + id[3:19]
	e.created = append(e.created, name)
	return name, nil
}

func (e *recordingEngine) Remove(_ context.Context, name string) error {
	e.removed = append(e.removed, name)
	return nil
}

func TestWorkspaceOpenListClose(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, Attestor: nil}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version:   2,
		OwnerID:   "owner",
		Operation: protocol.OpWorkspaceOpen,
		Input:     json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-repo-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	data, _ := open.Data.(map[string]any)
	id, _ := data["workspaceId"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixWorkspace, id) {
		t.Fatalf("workspaceId %q", id)
	}
	if data["networkProfile"] != "network-none" {
		t.Fatalf("profile %v", data["networkProfile"])
	}

	replay := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version:   2,
		OwnerID:   "owner",
		Operation: protocol.OpWorkspaceOpen,
		Input:     json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-repo-001","networkProfile":"network-none"}`),
	})
	if !replay.OK {
		t.Fatalf("replay: %+v", replay)
	}
	replayData, _ := replay.Data.(map[string]any)
	if replayData["workspaceId"] != id {
		t.Fatalf("idempotency did not reuse id: %v vs %s", replayData["workspaceId"], id)
	}

	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceList, Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}

	closed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version:   2,
		OwnerID:   "owner",
		Operation: protocol.OpWorkspaceClose,
		Input:     json.RawMessage(`{"workspaceId":"` + id + `"}`),
	})
	if !closed.OK {
		t.Fatalf("close: %+v", closed)
	}
}

func TestRejectsCredentialedURLAndBridge(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Operation: protocol.OpWorkspaceOpen,
		Input:     json.RawMessage(`{"repositoryUrl":"https://user:token@github.com/org/repo","idempotencyKey":"open-repo-002"}`),
	})
	if got.OK || got.Error == nil || got.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("credentialed URL: %+v", got)
	}
	got = svc.Execute(context.Background(), protocol.RunnerRequest{
		Operation: protocol.OpWorkspaceOpen,
		Input:     json.RawMessage(`{"repositoryUrl":"https://127.0.0.1/repo.git","idempotencyKey":"open-repo-loopback"}`),
	})
	if got.OK {
		t.Fatal("loopback repository host must fail")
	}
	got = svc.Execute(context.Background(), protocol.RunnerRequest{
		Operation: protocol.OpWorkspaceOpen,
		Input:     json.RawMessage(`{"repositoryUrl":"https://github.com/org/repo","idempotencyKey":"open-repo-003","networkMode":"bridge"}`),
	})
	if got.OK {
		t.Fatal("networkMode must be rejected")
	}
}

func TestDependencyAccessFailClosed(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.DependencyAccess, Attestor: nil}, nil, nil)
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Operation: protocol.OpWorkspaceOpen,
		Input:     json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-repo-004","networkProfile":"dependency-access"}`),
	})
	if got.OK || got.Error == nil || got.Error.Code != protocol.ErrorDependencyEgressUnavailable {
		t.Fatalf("expected fail-closed attestation, got %+v", got)
	}
	_ = sandbox.DefaultNetworkProfile
}

func TestUnknownStillInvalid(t *testing.T) {
	svc := NewService(Config{}, nil, nil)
	got := svc.Execute(context.Background(), protocol.RunnerRequest{Operation: "not_a_tool"})
	if got.OK || got.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("%+v", got)
	}
}

func TestWorkspaceCloseRemovesOnlyManagedContainer(t *testing.T) {
	eng := &recordingEngine{}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, eng)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-repo-close-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	data, _ := open.Data.(map[string]any)
	id, _ := data["workspaceId"].(string)
	if _, ok := data["containerName"]; ok {
		t.Fatal("public envelope must not expose containerName")
	}
	closed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceClose,
		Input: json.RawMessage(`{"workspaceId":"` + id + `"}`),
	})
	if !closed.OK {
		t.Fatalf("close: %+v", closed)
	}
	if len(eng.created) != 1 || len(eng.removed) != 1 {
		t.Fatalf("created=%v removed=%v", eng.created, eng.removed)
	}
	if eng.removed[0] != eng.created[0] {
		t.Fatalf("close must remove the managed container %s, not %s", eng.created[0], eng.removed[0])
	}
	if closed.Data.(map[string]any)["status"] != "CLOSED" {
		t.Fatalf("status %+v", closed.Data)
	}
}

func TestWorkspaceOpenClonesWithStdinTokenOnly(t *testing.T) {
	var seenArgs []string
	var seenStdin string
	cloner := &git.Cloner{Engine: sandbox.Engine{
		Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
			seenArgs = append([]string{}, args...)
			seenStdin = stdin
			return sandbox.Result{ExitCode: 0, Stdout: "cloned"}, nil
		},
	}}
	svc := NewService(Config{
		NetworkProfile: protocol.NetworkNone,
		JobsRoot:       t.TempDir(),
		ExecutorImage:  "cloud-harness-executor:local",
	}, nil, nil).WithCloner(cloner)
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-clone-001","networkProfile":"network-none"}`),
	})
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(strings.Join(seenArgs, " "), "clone-helper.sh") {
		t.Fatalf("missing helper: %v", seenArgs)
	}
	if git.ArgsContainSecret(seenArgs, seenStdin) && seenStdin != "" {
		t.Fatal("token in argv")
	}
	if strings.Contains(got.Message, "ghs_") {
		t.Fatal("token leaked in MCP result")
	}
	data, _ := got.Data.(map[string]any)
	if _, ok := data["token"]; ok {
		t.Fatal("token field on public envelope")
	}
}

func TestGitFetchUsesTransferHelperStdinOnly(t *testing.T) {
	var seen [][]string
	var stdin []string
	cloner := &git.Cloner{Engine: sandbox.Engine{
		Run: func(_ context.Context, args []string, in string) (sandbox.Result, error) {
			seen = append(seen, append([]string{}, args...))
			stdin = append(stdin, in)
			return sandbox.Result{ExitCode: 0, Stdout: "ok"}, nil
		},
	}}
	svc := NewService(Config{
		NetworkProfile: protocol.NetworkNone,
		JobsRoot:       t.TempDir(),
		ExecutorImage:  "cloud-harness-executor:local",
	}, nil, nil).WithCloner(cloner)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-fetch-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitFetch,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","remote":"origin"}`),
	})
	if !got.OK {
		t.Fatalf("fetch: %+v", got)
	}
	joined := ""
	for _, args := range seen {
		line := strings.Join(args, " ")
		joined += line + "\n"
		if git.ArgsContainSecret(args, "ghs_") {
			t.Fatal("token in argv")
		}
	}
	if !strings.Contains(joined, "git-transfer-helper.sh") {
		t.Fatalf("missing transfer helper: %s", joined)
	}
	if !strings.Contains(joined, "--network none") {
		t.Fatal("import must stay network-none")
	}
	denied := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitFetch,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","refspec":"--upload-pack=evil"}`),
	})
	if denied.OK || denied.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("evil refspec: %+v", denied)
	}
	push := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitPush,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","refspec":"HEAD:refs/heads/main"}`),
	})
	if push.OK || push.Error.Code != protocol.ErrorRepositoryOperationNotAuthorized {
		t.Fatalf("push without app: %+v", push)
	}
}

func TestWorkspaceLeaseRenewCapsAtHardExpiry(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, IdleTTL: time.Minute, WallTTL: 2 * time.Minute}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-lease-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	renewed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceLeaseRenew,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","extensionSeconds":86400}`),
	})
	if !renewed.OK {
		t.Fatalf("renew: %+v", renewed)
	}
	closed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceClose,
		Input: json.RawMessage(`{"workspaceId":"` + id + `"}`),
	})
	if !closed.OK {
		t.Fatalf("close: %+v", closed)
	}
	again := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceLeaseRenew,
		Input: json.RawMessage(`{"workspaceId":"` + id + `"}`),
	})
	if again.OK || again.Error.Code != protocol.ErrorExpired {
		t.Fatalf("closed renew: %+v", again)
	}
}

func TestWorkspaceRecoverResumeAndSetActive(t *testing.T) {
	st := store.NewMemory()
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, IdleTTL: time.Minute, WallTTL: 15 * time.Minute}, st, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-recover-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	if _, ok := st.UpdateStatus(id, store.StatusExpiredRecoverable); !ok {
		t.Fatal("expire")
	}
	recovered := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceRecover,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","mode":"resume"}`),
	})
	if !recovered.OK {
		t.Fatalf("recover: %+v", recovered)
	}
	data := recovered.Data.(map[string]any)
	if data["status"] != "ACTIVE" {
		t.Fatalf("status %v", data["status"])
	}
	set := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceSetActive,
		Input: json.RawMessage(`{"workspaceId":"` + id + `"}`),
	})
	if !set.OK {
		t.Fatalf("set active: %+v", set)
	}
	ctx := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceContext,
		Input: json.RawMessage(`{}`),
	})
	if !ctx.OK {
		t.Fatalf("context: %+v", ctx)
	}
	if ctx.Data.(map[string]any)["workspaceId"] != id {
		t.Fatalf("preferred context %+v", ctx.Data)
	}
	closed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceClose,
		Input: json.RawMessage(`{"workspaceId":"` + id + `"}`),
	})
	if !closed.OK {
		t.Fatal(closed)
	}
	again := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceRecover,
		Input: json.RawMessage(`{"workspaceId":"` + id + `"}`),
	})
	if again.OK || again.Error.Code != protocol.ErrorExpired {
		t.Fatalf("closed recover: %+v", again)
	}
}

func TestWorkspaceRecoverStatusPatchAndExportGates(t *testing.T) {
	jobs := t.TempDir()
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil).WithCloner(&git.Cloner{Engine: sandbox.Engine{
		Run: func(context.Context, []string, string) (sandbox.Result, error) {
			return sandbox.Result{ExitCode: 0}, nil
		},
	}})
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-recover-modes-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	repo := filepath.Join(jobs, id, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s (%v)", args, out, err)
		}
	}
	runGit("init")
	runGit("-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "--allow-empty", "-m", "seed")
	status := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceRecover,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","mode":"status"}`),
	})
	if !status.OK {
		t.Fatalf("status: %+v", status)
	}
	if _, ok := status.Data.(map[string]any)["workspace"]; !ok {
		t.Fatalf("missing workspace envelope: %+v", status.Data)
	}
	dash := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceRecover,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","mode":"export","targetBranch":"--upload-pack"}`),
	})
	if dash.OK || dash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash export: %+v", dash)
	}
	exp := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceRecover,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","mode":"export","targetBranch":"recovered"}`),
	})
	if exp.OK || exp.Error.Code != protocol.ErrorRepositoryOperationNotAuthorized {
		t.Fatalf("export without app: %+v", exp)
	}
}

func TestGitIdentitySetAndStatus(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	status := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitIdentityStatus, Input: json.RawMessage(`{}`),
	})
	if !status.OK {
		t.Fatalf("%+v", status)
	}
	data := status.Data.(map[string]any)
	if data["source"] != "default" || data["email"] != "agent@cloud-harness.local" {
		t.Fatalf("%v", data)
	}
	set := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitIdentitySet,
		Input: json.RawMessage(`{"name":"Alice Developer","email":"alice@example.com"}`),
	})
	if !set.OK {
		t.Fatalf("set: %+v", set)
	}
	again := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitIdentityStatus, Input: json.RawMessage(`{}`),
	})
	got := again.Data.(map[string]any)
	if got["name"] != "Alice Developer" || got["source"] != "owner" {
		t.Fatalf("%v", got)
	}
	bad := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitIdentitySet,
		Input: json.RawMessage(`{"name":"Alice","email":"not-an-email"}`),
	})
	if bad.OK || bad.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("bad email: %+v", bad)
	}
}

func TestGitHubReadRejectsWriteAndMissingApp(t *testing.T) {
	called := 0
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: t.TempDir()}, nil, nil).WithCloner(&git.Cloner{Engine: sandbox.Engine{
		Run: func(_ context.Context, args []string, _ string) (sandbox.Result, error) {
			called++
			if strings.Contains(strings.Join(args, " "), "gh-helper.sh") {
				t.Fatal("github helper must not run without an App token")
			}
			return sandbox.Result{ExitCode: 0}, nil
		},
	}})
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-gh-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	writeOnRead := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubRead,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","action":"pr_create","title":"x","head":"feat"}`),
	})
	if writeOnRead.OK || writeOnRead.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("write via read: %+v", writeOnRead)
	}
	missing := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubRead,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","action":"pr_list"}`),
	})
	if missing.OK || missing.Error.Code != protocol.ErrorRepositoryOperationNotAuthorized {
		t.Fatalf("missing app: %+v", missing)
	}
	if called == 0 {
		t.Fatal("clone helper should still run on open")
	}
}
