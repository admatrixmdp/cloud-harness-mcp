package agent

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
)

type fakeDocker struct {
	mu    sync.Mutex
	calls [][]string
	fail  map[string]int
}

func (f *fakeDocker) Invoke(_ context.Context, args []string, _ string) (sandbox.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := append([]string{}, args...)
	f.calls = append(f.calls, copied)
	key := args[0]
	if len(args) > 1 {
		key = args[0] + " " + args[1]
	}
	if code, ok := f.fail[key]; ok {
		return sandbox.Result{ExitCode: code, Stderr: "boom"}, nil
	}
	return sandbox.Result{ExitCode: 0}, nil
}

func TestLauncherCreatesInternalNetworkWithoutMountsOrSecrets(t *testing.T) {
	docker := &fakeDocker{}
	l := &Launcher{
		Docker: docker, InstanceID: "local", Image: "cloud-harness-agent:local",
		GatewayURL: "http://model-gateway:3210", GatewayCtr: "cloud-harness-mcp-model-gateway-1",
	}
	agentID := "agent_" + strings.Repeat("b", 24)
	got, err := l.Launch(context.Background(), agentID, "ws_abcdefghijklmnopqrstuvwx", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.ContainerName, "ch-agent-") || !strings.HasPrefix(got.NetworkName, "ch-agent-net-") {
		t.Fatalf("%+v", got)
	}
	joined := ""
	sawNetwork := false
	sawConnect := false
	sawRun := false
	for _, call := range docker.calls {
		line := strings.Join(call, " ")
		joined += line + "\n"
		if strings.HasPrefix(line, "network create") {
			sawNetwork = true
			if !strings.Contains(line, "--internal") {
				t.Fatal("agent network must be internal")
			}
		}
		if strings.HasPrefix(line, "network connect") {
			sawConnect = true
		}
		if call[0] == "run" {
			sawRun = true
			if err := ValidateRunArgs(call); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !sawNetwork || !sawConnect || !sawRun {
		t.Fatalf("calls %s", joined)
	}
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--volume") || strings.Contains(joined, "OPENAI") {
		t.Fatalf("isolation leak: %s", joined)
	}
}

func TestLauncherCleansUpWhenRunFails(t *testing.T) {
	docker := &fakeDocker{fail: map[string]int{"run --interactive": 1, "run": 1}}
	l := &Launcher{
		Docker: docker, InstanceID: "local", Image: "cloud-harness-agent:local",
		GatewayURL: "http://model-gateway:3210",
	}
	_, err := l.Launch(context.Background(), "agent_"+strings.Repeat("c", 24), "ws_abcdefghijklmnopqrstuvwx", 1)
	if err == nil {
		t.Fatal("expected launch failure")
	}
	sawRm := false
	sawNetRm := false
	for _, call := range docker.calls {
		if call[0] == "rm" {
			sawRm = true
		}
		if len(call) >= 2 && call[0] == "network" && call[1] == "rm" {
			sawNetRm = true
		}
	}
	if !sawRm || !sawNetRm {
		t.Fatalf("cleanup missing: %+v", docker.calls)
	}
}
