package runner

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

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
