package runner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/agent"
	"github.com/bestagentkits/cloud-harness-mcp/internal/artifacts"
	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
	"github.com/bestagentkits/cloud-harness-mcp/internal/grants"
	"github.com/bestagentkits/cloud-harness-mcp/internal/hooks"
	"github.com/bestagentkits/cloud-harness-mcp/internal/knowledge"
	"github.com/bestagentkits/cloud-harness-mcp/internal/memories"
	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
	"github.com/bestagentkits/cloud-harness-mcp/internal/typesafe"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
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

type okAttestor struct{}

func (okAttestor) Verify(context.Context) (bool, string, error) { return true, "", nil }

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

func TestRunWorkerConfinesPathsAndInjectsGitIdentity(t *testing.T) {
	jobs := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("leak"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-worker-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	repo := filepath.Join(jobs, id, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "note.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpFilesList,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","path":"."}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	escaped := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpFilesRead,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","path":"../secret.txt"}`),
	})
	if escaped.OK || escaped.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("path escape: %+v", escaped)
	}
	expired := store.NewMemory()
	expiredSvc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, expired, nil)
	expiredOpen := expiredSvc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-worker-expired","networkProfile":"network-none"}`),
	})
	if !expiredOpen.OK {
		t.Fatalf("expired open: %+v", expiredOpen)
	}
	expiredID := expiredOpen.Data.(map[string]any)["workspaceId"].(string)
	if _, ok := expired.UpdateStatus(expiredID, store.StatusExpiredRecoverable); !ok {
		t.Fatal("expire")
	}
	blocked := expiredSvc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpFilesList,
		Input: json.RawMessage(`{"workspaceId":"` + expiredID + `","path":"."}`),
	})
	if blocked.OK || blocked.Error.Code != protocol.ErrorExpired {
		t.Fatalf("expired worker: %+v", blocked)
	}
	set := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitIdentitySet,
		Input: json.RawMessage(`{"name":"Alice Developer","email":"alice@example.com"}`),
	})
	if !set.OK {
		t.Fatalf("identity: %+v", set)
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
	runGit("add", "note.txt")
	committed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitCommit,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","message":"test: note"}`),
	})
	if !committed.OK {
		t.Fatalf("commit: %+v", committed)
	}
	data := committed.Data.(map[string]any)
	if data["authorName"] != "Alice Developer" || data["authorEmail"] != "alice@example.com" {
		t.Fatalf("identity not injected: %+v", data)
	}
	dash := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitCheckout,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","ref":"--help"}`),
	})
	if dash.OK || dash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash checkout: %+v", dash)
	}
}

func TestRunWorkerDispatchesDockerExecWhenAttached(t *testing.T) {
	jobs := t.TempDir()
	var capturedArgs []string
	var capturedStdin string
	docker := &sandbox.Engine{
		Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
			capturedArgs = append([]string{}, args...)
			capturedStdin = stdin
			return sandbox.Result{Stdout: `{"ok":true,"message":"files listed","data":{"entries":[]},"truncated":false}`}, nil
		},
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil).WithDocker(docker)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-worker-exec-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpFilesList,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","path":"."}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	if err := sandbox.ValidateWorkerExecArgs(capturedArgs); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(capturedArgs, " ")
	if !strings.Contains(joined, "exec") || !strings.Contains(joined, "worker-runner.sh") {
		t.Fatalf("expected docker exec: %s", joined)
	}
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--privileged") {
		t.Fatalf("leaky exec: %s", joined)
	}
	if !strings.Contains(capturedStdin, `"operation":"files_list"`) {
		t.Fatalf("stdin: %s", capturedStdin)
	}
	data, _ := listed.Data.(map[string]any)
	opID, _ := data["operationId"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixOperation, opID) {
		t.Fatalf("operationId %q", opID)
	}
	missing := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil).WithDocker(&sandbox.Engine{
		Run: func(context.Context, []string, string) (sandbox.Result, error) {
			t.Fatal("must not exec without a container")
			return sandbox.Result{}, nil
		},
	})
	opened := missing.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-worker-exec-missing","networkProfile":"network-none"}`),
	})
	if !opened.OK {
		t.Fatalf("open missing: %+v", opened)
	}
	wsID := opened.Data.(map[string]any)["workspaceId"].(string)
	rec, ok := missing.store.Get(wsID)
	if !ok {
		t.Fatal("record")
	}
	rec.ContainerName = ""
	if err := missing.store.Put(rec); err != nil {
		t.Fatal(err)
	}
	blocked := missing.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpFilesList,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","path":"."}`),
	})
	if blocked.OK || blocked.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("missing container: %+v", blocked)
	}
}

func TestSessionsAndTasksUsePersistentDockerExec(t *testing.T) {
	jobs := t.TempDir()
	var spawned [][]string
	var extra [][]string
	docker := &sandbox.Engine{
		Run: func(context.Context, []string, string) (sandbox.Result, error) {
			t.Fatal("sessions must not use one-shot worker invoke")
			return sandbox.Result{}, nil
		},
		Start: func(args []string, env []string) (*exec.Cmd, error) {
			spawned = append(spawned, append([]string{}, args...))
			extra = append(extra, append([]string{}, env...))
			cmd := exec.Command("sleep", "30")
			return cmd, nil
		},
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil).WithDocker(docker)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-interactive-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	if err := os.MkdirAll(filepath.Join(jobs, id, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	sess := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSessionsOpen,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","name":"review","cwd":".","idempotencyKey":"sess-key-01"}`),
	})
	if !sess.OK {
		t.Fatalf("session: %+v", sess)
	}
	if len(spawned) != 1 {
		t.Fatalf("spawn count %d", len(spawned))
	}
	if err := sandbox.ValidateInteractiveExecArgs(spawned[0]); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(spawned[0], " ")
	if strings.Contains(joined, "worker-runner.sh") || strings.Contains(joined, "docker.sock") {
		t.Fatalf("leaky session exec: %s", joined)
	}
	task := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpTasksRun,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","command":"echo secret-token","cwd":".","idempotencyKey":"task-key-01","timeoutMs":5000}`),
	})
	if !task.OK {
		t.Fatalf("task: %+v", task)
	}
	if len(spawned) != 2 {
		t.Fatalf("task spawn count %d", len(spawned))
	}
	if err := sandbox.ValidateTaskExecArgs(spawned[1]); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(spawned[1], " ")
	if strings.Contains(joined, "secret-token") || strings.Contains(joined, "CH_COMMAND=") {
		t.Fatalf("command leaked into argv: %s", joined)
	}
	if len(extra[1]) != 1 || extra[1][0] != "CH_COMMAND=echo secret-token" {
		t.Fatalf("command env: %v", extra[1])
	}
	sessID, _ := sess.Data.(map[string]any)["id"].(string)
	closed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSessionsClose,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","sessionId":"` + sessID + `"}`),
	})
	if !closed.OK {
		t.Fatalf("close: %+v", closed)
	}
}

func TestSecretsListReturnsMetadataNeverPlaintext(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ring, err := secrets.NewKeyring(1, []secrets.KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{9}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	sec, err := secrets.OpenMetadata(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	envID := protocol.NewOpaqueID(protocol.PrefixEnvironment)
	if _, err := sec.Create("owner", "global", "GLOBAL_CONFIG", "global_secret_abc123", "Global app config", now); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.Create("owner", envID, "STRIPE_KEY", "sk_live_verysecret12345", "Stripe production secret", now); err != nil {
		t.Fatal(err)
	}
	if _, err := sec.Create("owner", envID, "DB_PASS", "db_pass_secret999", "Database master password", now); err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithSecrets(sec)
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSecretsList,
		Input: json.RawMessage(`{"environmentId":"` + envID + `"}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	raw, _ := json.Marshal(listed)
	for _, secret := range []string{"global_secret_abc123", "sk_live_verysecret12345", "db_pass_secret999"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("plaintext leaked: %s", secret)
		}
	}
	data := listed.Data.(map[string]any)
	items := secretMaps(data["secrets"])
	if len(items) != 3 {
		t.Fatalf("want 3 secrets, got %+v", data["secrets"])
	}
	for _, m := range items {
		if _, ok := m["value"]; ok {
			t.Fatal("value field")
		}
		if m["name"] == "STRIPE_KEY" && m["scope"] != "environment" {
			t.Fatalf("%+v", m)
		}
		if m["name"] == "GLOBAL_CONFIG" && m["scope"] != "global" {
			t.Fatalf("%+v", m)
		}
	}
	query := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSecretsList,
		Input: json.RawMessage(`{"environmentId":"` + envID + `","query":"stripe"}`),
	})
	if !query.OK {
		t.Fatalf("query: %+v", query)
	}
	qitems := secretMaps(query.Data.(map[string]any)["secrets"])
	if len(qitems) != 1 || qitems[0]["name"] != "STRIPE_KEY" {
		t.Fatalf("query %+v", query.Data)
	}
	empty := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	none := empty.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSecretsList, Input: json.RawMessage(`{}`),
	})
	if !none.OK {
		t.Fatalf("empty: %+v", none)
	}
}

func secretMaps(raw any) []map[string]any {
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

func TestArtifactsSnapshotListReadRestoreDelete(t *testing.T) {
	jobs := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "artifacts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	art, err := artifacts.Open(db, artifacts.Options{Root: filepath.Join(t.TempDir(), "objects-root")})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil).WithArtifacts(art)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-art-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	repo := filepath.Join(jobs, id, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("data for snapshot and restore test 456")
	if err := os.WriteFile(filepath.Join(repo, "analysis.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	snap := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpArtifactsSnapshot,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","path":"analysis.json","logicalName":"analysis.json"}`),
	})
	if !snap.OK {
		t.Fatalf("snapshot: %+v", snap)
	}
	data := snap.Data.(map[string]any)
	artID := data["artifactId"].(string)
	if data["logicalName"] != "analysis.json" {
		t.Fatalf("%+v", data)
	}
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpArtifactsList, Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	read := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpArtifactsRead,
		Input: json.RawMessage(`{"artifactId":"` + artID + `"}`),
	})
	if !read.OK {
		t.Fatalf("read: %+v", read)
	}
	foreign := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "other", Operation: protocol.OpArtifactsRead,
		Input: json.RawMessage(`{"artifactId":"` + artID + `"}`),
	})
	if foreign.OK || foreign.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("cross-principal: %+v", foreign)
	}
	mismatch := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpArtifactsRestore,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","artifactId":"` + artID + `","path":"out.txt","expectedSha256":"` + strings.Repeat("a", 64) + `"}`),
	})
	if mismatch.OK || mismatch.Error.Code != protocol.ErrorConflict {
		t.Fatalf("hash mismatch: %+v", mismatch)
	}
	restored := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpArtifactsRestore,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","artifactId":"` + artID + `","path":"context/analysis.json","overwrite":true}`),
	})
	if !restored.OK {
		t.Fatalf("restore: %+v", restored)
	}
	got, err := os.ReadFile(filepath.Join(repo, "context", "analysis.json"))
	if err != nil || string(got) != string(body) {
		t.Fatalf("restored file %q %v", got, err)
	}
	escape := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpArtifactsSnapshot,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","path":"../secret.txt","logicalName":"secret.txt"}`),
	})
	if escape.OK || escape.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("snapshot escape: %+v", escape)
	}
	del := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpArtifactsDelete,
		Input: json.RawMessage(`{"artifactId":"` + artID + `"}`),
	})
	if !del.OK {
		t.Fatalf("delete: %+v", del)
	}
	missing := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpArtifactsRead,
		Input: json.RawMessage(`{"artifactId":"` + artID + `"}`),
	})
	if missing.OK || missing.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("read after delete: %+v", missing)
	}
}

func TestMemoriesWriteListReadDeleteOnRunner(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "mem.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	memStore, err := memories.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithMemories(memStore)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"mem-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	wrote := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpMemoriesWrite,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"alpha","content":"runner note","tags":["keep"]}`),
	})
	if !wrote.OK {
		t.Fatalf("write: %+v", wrote)
	}
	if wrote.Data.(map[string]any)["content"] != "runner note" {
		t.Fatalf("write data %+v", wrote.Data)
	}
	dup := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpMemoriesWrite,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"alpha","content":"dup"}`),
	})
	if dup.OK || dup.Error.Code != protocol.ErrorConflict {
		t.Fatalf("dup: %+v", dup)
	}
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpMemoriesList,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `"}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	items := secretMaps(listed.Data.(map[string]any)["memories"])
	if len(items) != 1 || items[0]["name"] != "alpha" {
		t.Fatalf("list %+v", listed.Data)
	}
	if _, ok := items[0]["content"]; ok {
		t.Fatal("list must omit content")
	}
	read := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpMemoriesRead,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"alpha"}`),
	})
	if !read.OK || read.Data.(map[string]any)["content"] != "runner note" {
		t.Fatalf("read: %+v", read)
	}
	search := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpMemoriesSearch,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","query":"runner"}`),
	})
	if !search.OK {
		t.Fatalf("search: %+v", search)
	}
	del := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpMemoriesDelete,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"alpha","expectedGeneration":1}`),
	})
	if !del.OK {
		t.Fatalf("delete: %+v", del)
	}
}

func TestKnowledgeCreateListReadDeleteOnRunner(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kn.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	knStore, err := knowledge.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithKnowledge(knStore)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"kn-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	created := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeCreate,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","title":"Alpha","content":"keep knowledge","tags":["keep"]}`),
	})
	if !created.OK {
		t.Fatalf("create: %+v", created)
	}
	id := created.Data.(map[string]any)["id"].(string)
	dup := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeCreate,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","title":"Alpha","content":"dup"}`),
	})
	if dup.OK || dup.Error.Code != protocol.ErrorConflict {
		t.Fatalf("dup: %+v", dup)
	}
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeList,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `"}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	read := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeRead,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","id":"` + id + `"}`),
	})
	if !read.OK || read.Data.(map[string]any)["content"] != "keep knowledge" {
		t.Fatalf("read: %+v", read)
	}
	search := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeSearch,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","query":"keep"}`),
	})
	if !search.OK {
		t.Fatalf("search: %+v", search)
	}
	second := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeCreate,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","title":"Beta","content":"linked"}`),
	})
	if !second.OK {
		t.Fatalf("second: %+v", second)
	}
	id2 := second.Data.(map[string]any)["id"].(string)
	self := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeLink,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","sourceId":"` + id + `","targetId":"` + id + `"}`),
	})
	if self.OK || self.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("self-link: %+v", self)
	}
	linked := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeLink,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","sourceId":"` + id + `","targetId":"` + id2 + `","relation":"supports"}`),
	})
	if !linked.OK {
		t.Fatalf("link: %+v", linked)
	}
	graph := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeGraph,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","rootId":"` + id + `","depth":1}`),
	})
	if !graph.OK {
		t.Fatalf("graph: %+v", graph)
	}
	if graph.Data.(map[string]any)["truncated"] != false {
		t.Fatalf("truncated %+v", graph.Data)
	}
	unlinked := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeUnlink,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","sourceId":"` + id + `","targetId":"` + id2 + `"}`),
	})
	if !unlinked.OK {
		t.Fatalf("unlink: %+v", unlinked)
	}
	del := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeDelete,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","id":"` + id + `","expectedGeneration":1}`),
	})
	if !del.OK {
		t.Fatalf("delete: %+v", del)
	}
}

func TestKnowledgeDashboardAliasesSkipWorkspace(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "kn-dash.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	knStore, err := knowledge.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithKnowledge(knStore)
	created := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeDashboardCreate,
		Input: json.RawMessage(`{"kind":"memory","scope":"owner","title":"Owner note","content":"no workspace required","expectedGeneration":0}`),
	})
	if !created.OK {
		t.Fatalf("create: %+v", created)
	}
	id := created.Data.(map[string]any)["id"].(string)
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeDashboardList, Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	items, _ := listed.Data.(map[string]any)["items"].([]map[string]any)
	if len(items) != 1 || items[0]["id"] != id {
		t.Fatalf("list data %+v", listed.Data)
	}
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpKnowledgeDashboardGet,
		Input: json.RawMessage(`{"id":"` + id + `"}`),
	})
	if !got.OK {
		t.Fatalf("get: %+v", got)
	}
	foreign := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "other", Operation: protocol.OpKnowledgeDashboardGet,
		Input: json.RawMessage(`{"id":"` + id + `"}`),
	})
	if foreign.OK || foreign.Error == nil || foreign.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("foreign get: %+v", foreign)
	}
}

func TestHooksActivateDeactivateOnRunner(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "hooks.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hookStore, err := hooks.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithHooks(hookStore)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"hook-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bad := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpHooksActivate,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","manifestSha256":"short","events":["pre_commit"]}`),
	})
	if bad.OK || bad.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("bad digest: %+v", bad)
	}
	act := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpHooksActivate,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","manifestSha256":"` + sha + `","events":["pre_commit","post_commit"],"retentionSeconds":120}`),
	})
	if !act.OK {
		t.Fatalf("activate: %+v", act)
	}
	data := act.Data.(map[string]any)
	var rows []map[string]any
	switch raw := data["activations"].(type) {
	case []map[string]any:
		rows = raw
	case []any:
		for _, row := range raw {
			rows = append(rows, row.(map[string]any))
		}
	}
	if len(rows) != 2 {
		t.Fatalf("activations: %+v", data)
	}
	deact := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpHooksDeactivate,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","events":["pre_commit"]}`),
	})
	if !deact.OK {
		t.Fatalf("deactivate: %+v", deact)
	}
	all := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpHooksDeactivate,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `"}`),
	})
	if !all.OK {
		t.Fatalf("deactivate all: %+v", all)
	}
}

func TestSkillsRunRequiresPrivilegeGrant(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "grants.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	grantStore, err := grants.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithGrants(grantStore)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"skill-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	denied := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillsRun,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"tdd","script":"run.sh","expectedSha256":"` + sha + `"}`),
	})
	if denied.OK || denied.Error.Code != protocol.ErrorPrivilegeApprovalRequired {
		t.Fatalf("denied: %+v", denied)
	}
	grantReq, _ := denied.Error.GrantRequest.(map[string]any)
	grantID, _ := grantReq["grantId"].(string)
	if grantID == "" {
		t.Fatalf("grantRequest %+v", denied.Error)
	}
	if !grantStore.Approve("owner", grantID) {
		t.Fatal("approve")
	}
	bad := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillsRun,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"tdd","script":"run.sh","expectedSha256":"` + sha + `","approvalGrantToken":"pvg_missing"}`),
	})
	if bad.OK || bad.Error.Code != protocol.ErrorForbidden {
		t.Fatalf("bad token: %+v", bad)
	}
	missingHelper := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillsRun,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"tdd","script":"run.sh","expectedSha256":"` + sha + `","approvalGrantToken":"` + grantID + `"}`),
	})
	if missingHelper.OK || missingHelper.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("approved grant without docker must not fall back to local: %+v", missingHelper)
	}
}

func TestSkillsRunHelperContainerAfterGrant(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "grants.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	grantStore, err := grants.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	jobs := t.TempDir()
	var capturedArgs []string
	var capturedStdin string
	docker := &sandbox.Engine{
		Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
			capturedArgs = append([]string{}, args...)
			capturedStdin = stdin
			return sandbox.Result{Stdout: `{"ok":true,"message":"Skill script exited with 0","data":{"output":"ok","exitCode":0,"executionMode":"local"},"truncated":false}`}, nil
		},
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil).WithGrants(grantStore).WithDocker(docker)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"skill-helper-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	if err := os.MkdirAll(filepath.Join(jobs, wsID, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	denied := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillsRun,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"tdd","script":"run.sh","expectedSha256":"` + sha + `"}`),
	})
	if denied.OK || denied.Error.Code != protocol.ErrorPrivilegeApprovalRequired {
		t.Fatalf("denied: %+v", denied)
	}
	grantID := denied.Error.GrantRequest.(map[string]any)["grantId"].(string)
	if !grantStore.Approve("owner", grantID) {
		t.Fatal("approve")
	}
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillsRun,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","name":"tdd","script":"run.sh","expectedSha256":"` + sha + `","approvalGrantToken":"` + grantID + `"}`),
	})
	if !got.OK {
		t.Fatalf("helper: %+v", got)
	}
	data, _ := got.Data.(map[string]any)
	if data["executionMode"] != "helper-container" {
		t.Fatalf("executionMode %+v", data)
	}
	if err := sandbox.ValidateSkillHelperArgs(capturedArgs); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(capturedArgs, " ")
	if strings.Contains(joined, grantID) || strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--user 0:0") {
		t.Fatalf("leaky helper argv: %s", joined)
	}
	if !strings.Contains(joined, "--network none") || !strings.Contains(joined, "--user 10001:10001") {
		t.Fatalf("hardening missing: %s", joined)
	}
	if strings.Contains(capturedStdin, grantID) || strings.Contains(capturedStdin, "approvalGrantToken") {
		t.Fatalf("grant token leaked onto helper stdin: %s", capturedStdin)
	}
	if !strings.Contains(capturedStdin, `"operation":"skills_run"`) {
		t.Fatalf("stdin payload: %s", capturedStdin)
	}
}

func initGitRepo(t *testing.T, root string) {
	t.Helper()
	cmds := [][]string{
		{"git", "init", "-b", "main"},
		{"git", "config", "user.name", "Test"},
		{"git", "config", "user.email", "test@example.com"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", args, out)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "add", "README.md")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add: %s", out)
	}
	cmd = exec.Command("git", "commit", "-m", "init")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("commit: %s", out)
	}
}

func TestWorkspaceFinalizePreflightAndLocalCommit(t *testing.T) {
	jobs := t.TempDir()
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"finalize-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	root := filepath.Join(jobs, wsID, "repo")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	initGitRepo(t, root)
	if err := os.WriteFile(filepath.Join(root, "conflict.txt"), []byte("<<<<<<< HEAD\na\n=======\nb\n>>>>>>> other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	add := exec.Command("git", "add", "conflict.txt")
	add.Dir = root
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage conflict: %s", out)
	}
	conflict := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceFinalize,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","commitMessage":"feat: with conflict","push":false}`),
	})
	if conflict.OK || conflict.Error.Code != protocol.ErrorConflict {
		t.Fatalf("conflict: %+v", conflict)
	}
	if conflict.Data.(map[string]any)["step"] != "preflight" {
		t.Fatalf("step %+v", conflict.Data)
	}
	if err := os.WriteFile(filepath.Join(root, "conflict.txt"), []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceFinalize,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","commitMessage":"feat: finalize locally","push":false}`),
	})
	if !ok.OK {
		t.Fatalf("finalize: %+v", ok)
	}
	if ok.Data.(map[string]any)["pushed"] != false {
		t.Fatalf("pushed %+v", ok.Data)
	}
	sha, _ := ok.Data.(map[string]any)["commitSha"].(string)
	if sha == "" {
		t.Fatalf("missing commitSha %+v", ok.Data)
	}
	dash := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceFinalize,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","commitMessage":"x","branch":"--help","push":false}`),
	})
	if dash.OK || dash.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("dash branch: %+v", dash)
	}
}

func TestWorkspaceFinalizeIdempotencyReplayAndConflict(t *testing.T) {
	jobs := t.TempDir()
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"finalize-open-idemp","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	root := filepath.Join(jobs, wsID, "repo")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	initGitRepo(t, root)
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceFinalize,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","commitMessage":"feat: one","push":false,"idempotencyKey":"finalize-once-01"}`),
	})
	if !first.OK {
		t.Fatalf("first: %+v", first)
	}
	sha := first.Data.(map[string]any)["commitSha"].(string)
	replay := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceFinalize,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","commitMessage":"feat: one","push":false,"idempotencyKey":"finalize-once-01"}`),
	})
	if !replay.OK {
		t.Fatalf("replay: %+v", replay)
	}
	if replay.Data.(map[string]any)["commitSha"] != sha {
		t.Fatalf("replay sha %+v", replay.Data)
	}
	conflict := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceFinalize,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","commitMessage":"feat: other","push":false,"idempotencyKey":"finalize-once-01"}`),
	})
	if conflict.OK || conflict.Error.Code != protocol.ErrorConflict {
		t.Fatalf("conflict: %+v", conflict)
	}
}

func TestSkillSuggestIsFailClosedWithoutTypeSafe(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	none := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillSuggest,
		Input: json.RawMessage(`{"prompt":"Please refactor the authentication middleware."}`),
	})
	if !none.OK {
		t.Fatalf("no workspace: %+v", none)
	}
	data := none.Data.(map[string]any)
	if data["suggested"] != nil || data["reason"] != "empty_roster" || data["outboundCalls"] != 0 {
		t.Fatalf("no workspace data %+v", data)
	}
	raw, _ := json.Marshal(none)
	if strings.Contains(string(raw), "authentication middleware") {
		t.Fatalf("prompt leaked: %s", raw)
	}
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"suggest-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillSuggest,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"Please refactor the authentication middleware."}`),
	})
	if !got.OK {
		t.Fatalf("configured workspace: %+v", got)
	}
	out := got.Data.(map[string]any)
	if out["suggested"] != nil || out["reason"] != "not_configured" || out["outboundCalls"] != 0 {
		t.Fatalf("workspace data %+v", out)
	}
	over := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillSuggest,
		Input: json.RawMessage(`{"prompt":"` + strings.Repeat("x", 8193) + `"}`),
	})
	if over.OK || over.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("oversize: %+v", over)
	}
}

func TestSkillSuggestTypeSafeHTTPSNeverEchoesPrompt(t *testing.T) {
	jobs := t.TempDir()
	calls := 0
	engine := typesafe.New(typesafe.Config{
		APIKey: func() string { return "ts_live_key" },
		RoundTrip: func(req *http.Request) (*http.Response, error) {
			calls++
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "ts_live_key") {
				t.Fatal("api key in outbound body")
			}
			if req.Header.Get("Authorization") != "Bearer ts_live_key" {
				t.Fatalf("authorization %q", req.Header.Get("Authorization"))
			}
			answers := map[string]any{
				"skill":                             map[string]any{"type": "choice", "choice": "tdd"},
				"acts_on_user_system":               map[string]any{"type": "noul", "noul": 1.0},
				"would_follow_documented_procedure": map[string]any{"type": "noul", "noul": 1.0},
				"prose_suffices":                    map[string]any{"type": "noul", "noul": 0.0},
			}
			if calls == 2 {
				answers["fits::tdd"] = map[string]any{"type": "noul", "noul": 0.9}
			}
			raw, _ := json.Marshal(map[string]any{"answers": answers, "usage": map[string]any{"input_tokens": 10, "output_tokens": 4}})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header)}, nil
		},
	})
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil).WithTypeSafe(engine)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"suggest-https-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	skillDir := filepath.Join(jobs, wsID, "repo", ".cloud-harness", "skills", "tdd")
	if err := os.MkdirAll(skillDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\ndescription: test driven development\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillSuggest,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"Please refactor the authentication middleware."}`),
	})
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "authentication middleware") || strings.Contains(string(raw), "ts_live_key") {
		t.Fatalf("leaked %s", raw)
	}
	suggested, _ := got.Data.(map[string]any)["suggested"].(map[string]any)
	if suggested["name"] != "tdd" {
		t.Fatalf("suggested %+v calls=%d", got.Data, calls)
	}
	if calls != 2 {
		t.Fatalf("calls %d", calls)
	}
}

func TestAgentSpawnStatusListCancelFailClosed(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"agent-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	missing := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"hi"}`),
	})
	if missing.OK || missing.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("missing key: %+v", missing)
	}
	spawn := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"Please refactor auth.","idempotencyKey":"agent-spawn-01","profileId":"coding-fast","proxyOperations":["files_list","files_read"]}`),
	})
	if !spawn.OK {
		t.Fatalf("spawn: %+v", spawn)
	}
	data := spawn.Data.(map[string]any)
	id, _ := data["agentId"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixAgent, id) {
		t.Fatalf("id %q", id)
	}
	if data["status"] != "FAILED" || data["replayed"] != false {
		t.Fatalf("spawn data %+v", data)
	}
	raw, _ := json.Marshal(spawn)
	if strings.Contains(string(raw), "Please refactor auth") {
		t.Fatalf("prompt leaked: %s", raw)
	}
	replay := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"Please refactor auth.","idempotencyKey":"agent-spawn-01","profileId":"coding-fast","proxyOperations":["files_list","files_read"]}`),
	})
	if !replay.OK || replay.Data.(map[string]any)["agentId"] != id || replay.Data.(map[string]any)["replayed"] != true {
		t.Fatalf("replay: %+v", replay)
	}
	conflict := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"other prompt","idempotencyKey":"agent-spawn-01","profileId":"coding-fast","proxyOperations":["files_list","files_read"]}`),
	})
	if conflict.OK || conflict.Error.Code != protocol.ErrorConflict {
		t.Fatalf("conflict: %+v", conflict)
	}
	st := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentStatus,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","agentId":"` + id + `"}`),
	})
	if !st.OK || st.Data.(map[string]any)["status"] != "FAILED" {
		t.Fatalf("status: %+v", st)
	}
	byKey := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentStatus,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","idempotencyKey":"agent-spawn-01"}`),
	})
	if !byKey.OK || byKey.Data.(map[string]any)["agentId"] != id {
		t.Fatalf("status by key: %+v", byKey)
	}
	both := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentStatus,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","agentId":"` + id + `","idempotencyKey":"agent-spawn-01"}`),
	})
	if both.OK || both.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("both lookup: %+v", both)
	}
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentList,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `"}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	agents := listed.Data.(map[string]any)["agents"]
	if len(asAnyMaps(agents)) != 1 {
		t.Fatalf("list %+v", listed.Data)
	}
	msg := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentMessage,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","agentId":"` + id + `","idempotencyKey":"agent-msg-01","mode":"steer","message":"keep going"}`),
	})
	if !msg.OK || msg.Data.(map[string]any)["state"] != "REJECTED" {
		t.Fatalf("message: %+v", msg)
	}
	msgReplay := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentMessage,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","agentId":"` + id + `","idempotencyKey":"agent-msg-01","mode":"steer","message":"keep going"}`),
	})
	if !msgReplay.OK || msgReplay.Data.(map[string]any)["replayed"] != true {
		t.Fatalf("message replay: %+v", msgReplay)
	}
	cancelled := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentCancel,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","agentId":"` + id + `"}`),
	})
	if !cancelled.OK {
		t.Fatalf("cancel: %+v", cancelled)
	}
	dep := NewService(Config{NetworkProfile: protocol.DependencyAccess, Attestor: okAttestor{}}, nil, nil)
	depOpen := dep.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"agent-open-dep","networkProfile":"dependency-access"}`),
	})
	if !depOpen.OK {
		t.Fatalf("dep open: %+v", depOpen)
	}
	depID := depOpen.Data.(map[string]any)["workspaceId"].(string)
	denied := dep.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + depID + `","prompt":"hi there agent","idempotencyKey":"agent-spawn-dep","profileId":"coding-fast","proxyOperations":["files_list"]}`),
	})
	if denied.OK || denied.Error.Code != protocol.ErrorConflict {
		t.Fatalf("network-none required: %+v", denied)
	}
}

type recordingDocker struct {
	calls [][]string
}

func (r *recordingDocker) Invoke(_ context.Context, args []string, _ string) (sandbox.Result, error) {
	r.calls = append(r.calls, append([]string{}, args...))
	return sandbox.Result{ExitCode: 0}, nil
}

func TestAgentSpawnRunsWhenLauncherWired(t *testing.T) {
	docker := &recordingDocker{}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithAgents(&agent.Launcher{
		Docker: docker, InstanceID: "local", Image: "cloud-harness-agent:local", GatewayURL: "http://model-gateway:3210",
	}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"agent-open-run","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	spawn := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"Please refactor auth.","idempotencyKey":"agent-spawn-run","profileId":"coding-fast","proxyOperations":["files_list","files_read"]}`),
	})
	if !spawn.OK {
		t.Fatalf("spawn: %+v", spawn)
	}
	data := spawn.Data.(map[string]any)
	if data["status"] != "RUNNING" || data["replayed"] != false {
		t.Fatalf("spawn data %+v", data)
	}
	raw, _ := json.Marshal(spawn)
	if strings.Contains(string(raw), "Please refactor auth") {
		t.Fatalf("prompt leaked: %s", raw)
	}
	joined := ""
	for _, call := range docker.calls {
		joined += strings.Join(call, " ") + "\n"
	}
	if !strings.Contains(joined, "network create") || !strings.Contains(joined, "--internal") {
		t.Fatalf("missing internal network: %s", joined)
	}
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--volume") {
		t.Fatalf("isolation leak: %s", joined)
	}
	id := data["agentId"].(string)
	cancelled := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentCancel,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","agentId":"` + id + `"}`),
	})
	if !cancelled.OK {
		t.Fatalf("cancel: %+v", cancelled)
	}
	sawRm := false
	for _, call := range docker.calls {
		if call[0] == "rm" {
			sawRm = true
		}
	}
	if !sawRm {
		t.Fatal("cancel must remove the agent container")
	}
}

func asAnyMaps(raw any) []map[string]any {
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
