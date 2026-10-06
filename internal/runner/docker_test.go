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
	var got []string
	inner := &sandbox.Engine{
		Image:      "cloud-harness-executor:local",
		InstanceID: "inst",
		Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
			got = append([]string{}, args...)
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
	if err := sandbox.ValidateCreateArgs(got); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--network bridge") {
		t.Fatalf("unsafe: %s", joined)
	}
	if !strings.Contains(joined, "/jobs/ws_abcdefghijklmnopqrstuvwx/repo:/workspace:rw") {
		t.Fatalf("missing repo mount: %s", joined)
	}
}
