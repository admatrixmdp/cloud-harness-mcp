package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/agent"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

type protocolPipes struct {
	stdin  *bytes.Buffer
	stdout *io.PipeReader
	w      *io.PipeWriter
}

func TestAgentMessageSentOnProtocolChannel(t *testing.T) {
	in := new(bytes.Buffer)
	pr, pw := io.Pipe()
	ch := agent.NewChannel(nopCloser{in}, pr)
	docker := &recordingDocker{}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithAgents(&agent.Launcher{
		Docker: docker, InstanceID: "local", Image: "cloud-harness-agent:local", GatewayURL: "http://model-gateway:3210",
	}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"agent-open-proto","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	spawn := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"Please refactor auth.","idempotencyKey":"agent-spawn-proto","profileId":"coding-fast","proxyOperations":["files_list"]}`),
	})
	if !spawn.OK || spawn.Data.(map[string]any)["status"] != "RUNNING" {
		t.Fatalf("spawn: %+v", spawn)
	}
	id := spawn.Data.(map[string]any)["agentId"].(string)
	rec := svc.agents.byID[id]
	rec.channel = ch
	msg := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentMessage,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","agentId":"` + id + `","idempotencyKey":"agent-msg-proto","mode":"steer","message":"keep going"}`),
	})
	if !msg.OK || msg.Data.(map[string]any)["state"] != "SENT" {
		t.Fatalf("message: %+v", msg)
	}
	wire := in.String()
	if !strings.Contains(wire, `"type":"message"`) || !strings.Contains(wire, "keep going") {
		t.Fatalf("wire %s", wire)
	}
	raw, _ := json.Marshal(msg)
	if strings.Contains(string(raw), "keep going") {
		t.Fatalf("message leaked into MCP result: %s", raw)
	}
	_ = pw
	_ = pr
}

type nopCloser struct{ *bytes.Buffer }

func (nopCloser) Close() error { return nil }

func TestStartRecordRedactsPromptFromMCP(t *testing.T) {
	in := new(bytes.Buffer)
	ch := agent.NewChannel(nopCloser{in}, bytes.NewReader(nil))
	docker := &recordingDocker{}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	svc.agents.withRuntime(&agent.Launcher{
		Docker: docker, InstanceID: "local", Image: "cloud-harness-agent:local", GatewayURL: "http://model-gateway:3210",
	}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"agent-open-start","networkProfile":"network-none"}`),
	})
	wsID := open.Data.(map[string]any)["workspaceId"].(string)
	spawn := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpAgentSpawn,
		Input: json.RawMessage(`{"workspaceId":"` + wsID + `","prompt":"Please refactor auth.","idempotencyKey":"agent-spawn-start","profileId":"coding-fast","proxyOperations":["files_list"]}`),
	})
	if !spawn.OK {
		t.Fatalf("spawn %+v", spawn)
	}
	id := spawn.Data.(map[string]any)["agentId"].(string)
	rec := svc.agents.byID[id]
	if rec.channel != nil {
		t.Fatal("invoke-only launcher must not attach a live channel")
	}
	if err := ch.Send(agent.StartRecord{Type: "start", RequestID: "r", AgentID: id, Prompt: "Please refactor auth.", Tools: rec.proxyOperations, Gateway: agent.StartGateway{Profile: "coding-fast", Lease: "lease_secret_xxxxxxxxxxxxxxxxxxxxxxx"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(in.String(), "Please refactor auth") {
		t.Fatal("start record must carry prompt on the wire")
	}
	raw, _ := json.Marshal(spawn)
	if strings.Contains(string(raw), "Please refactor auth") || strings.Contains(string(raw), "lease_secret") {
		t.Fatalf("leaked %s", raw)
	}
	_ = sync.Mutex{}
}
