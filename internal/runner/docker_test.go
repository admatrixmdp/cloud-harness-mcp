package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestDockerEngineCreateUsesPolicy(t *testing.T) {
	var calls [][]string
	inner := &sandbox.Engine{
		Image:      "cloud-harness-executor:local",
		InstanceID: "inst",
		Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
			copied := append([]string{}, args...)
			calls = append(calls, copied)
			return sandbox.Result{ExitCode: 0}, nil
		},
	}
	eng := DockerEngine{Inner: inner, JobsRoot: "/jobs"}
	name, err := eng.Create(context.Background(), store.Record{
		ID:             "ws_abcdefghijklmnopqrstuvwx",
		NetworkProfile: protocol.NetworkNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "cloud-harness-ws-") {
		t.Fatalf("name %s", name)
	}
	if len(calls) < 2 || calls[0][0] != "create" || calls[1][0] != "start" || calls[1][1] != name {
		t.Fatalf("create must be followed by start: %v", calls)
	}
	if err := sandbox.ValidateCreateArgs(calls[0]); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls[0], " ")
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--network bridge") {
		t.Fatalf("unsafe: %s", joined)
	}
	if !strings.Contains(joined, "/jobs/ws_abcdefghijklmnopqrstuvwx/repo:/workspace:rw") {
		t.Fatalf("missing repo mount: %s", joined)
	}
}

func TestDockerEngineCreateRemovesContainerWhenStartFails(t *testing.T) {
	var calls [][]string
	inner := &sandbox.Engine{
		Image:      "cloud-harness-executor:local",
		InstanceID: "inst",
		Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
			copied := append([]string{}, args...)
			calls = append(calls, copied)
			if args[0] == "start" {
				return sandbox.Result{ExitCode: 1, Stderr: "boom"}, nil
			}
			return sandbox.Result{ExitCode: 0}, nil
		},
	}
	eng := DockerEngine{Inner: inner, JobsRoot: "/jobs"}
	if _, err := eng.Create(context.Background(), store.Record{
		ID:             "ws_abcdefghijklmnopqrstuvwx",
		NetworkProfile: protocol.NetworkNone,
	}); err == nil {
		t.Fatal("start failure must surface")
	}
	sawRm := false
	for _, call := range calls {
		if call[0] == "rm" {
			sawRm = true
		}
	}
	if !sawRm {
		t.Fatalf("failed start must remove the container: %v", calls)
	}
}
