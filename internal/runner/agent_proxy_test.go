package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/agent"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestAgentProxyGrantsOnlyListedOperations(t *testing.T) {
	in := new(bytes.Buffer)
	pr, pw := io.Pipe()
	ch := agent.NewChannel(nopCloser{in}, pr)
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"agent-open-proxy","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	spawn := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"hi","idempotencyKey":"agent-spawn-proxy","profileId":"coding-fast","proxyOperations":["files_list"]}`),
	})
	id := spawn.Data.(map[string]any)["agentId"].(string)
	rec := svc.agents.byID[id]
	rec.status = "RUNNING"
	rec.channel = ch
	rec.proxyOperations = []string{"files_list"}

	svc.agents.proxyTool(rec, agent.OutputRecord{
		Type: "tool_request", RequestID: "req-denied", Operation: "files_write", Input: json.RawMessage(`{"path":"x"}`),
	})
	if !strings.Contains(in.String(), "proxy operation is not granted") {
		t.Fatalf("denied write: %s", in.String())
	}
	in.Reset()
	svc.agents.proxyTool(rec, agent.OutputRecord{
		Type: "tool_request", RequestID: "req-ok", Operation: "files_list", Input: json.RawMessage(`{}`),
	})
	if !strings.Contains(in.String(), `"type":"tool_result"`) {
		t.Fatalf("granted list: %s", in.String())
	}
	if !strings.Contains(in.String(), `"workspaceId"`) && !strings.Contains(in.String(), "files_list") {
		// result envelope should not echo the prompt
	}
	if strings.Contains(in.String(), `"prompt"`) {
		t.Fatal("prompt leaked onto tool_result")
	}
	in.Reset()
	svc.agents.proxyTool(rec, agent.OutputRecord{
		Type: "tool_request", RequestID: "req-ok", Operation: "files_list", Input: json.RawMessage(`{}`),
	})
	if !strings.Contains(in.String(), "duplicate proxy request ID") {
		t.Fatalf("duplicate: %s", in.String())
	}
	_ = pw.Close()
}

func TestAgentProxyInjectsWorkspaceId(t *testing.T) {
	var seen protocol.RunnerRequest
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	svc.agents.exec = func(_ context.Context, req protocol.RunnerRequest) protocol.ToolResult {
		seen = req
		return protocol.Success("listed", map[string]any{"entries": []any{}})
	}
	in := new(bytes.Buffer)
	ch := agent.NewChannel(nopCloser{in}, bytes.NewReader(nil))
	rec := &agentRecord{
		id: "agent_" + strings.Repeat("p", 24), ownerID: "owner", workspaceID: "ws_abcdefghijklmnopqrstuvwx",
		status: "RUNNING", proxyOperations: []string{"files_read"}, channel: ch,
	}
	svc.agents.proxyTool(rec, agent.OutputRecord{
		Type: "tool_request", RequestID: "req-read", Operation: "files_read", Input: json.RawMessage(`{"path":"README.md"}`),
	})
	if seen.Operation != protocol.OpFilesRead {
		t.Fatalf("op %s", seen.Operation)
	}
	var payload map[string]any
	_ = json.Unmarshal(seen.Input, &payload)
	if payload["workspaceId"] != rec.workspaceID || payload["path"] != "README.md" {
		t.Fatalf("%v", payload)
	}
	if !strings.Contains(in.String(), `"type":"tool_result"`) || !strings.Contains(in.String(), `"isError":false`) {
		t.Fatalf("result %s", in.String())
	}
}
