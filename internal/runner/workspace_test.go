package runner

import (
	"context"
	"encoding/json"
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
