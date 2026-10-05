//go:build docker

package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestLiveDockerCreateArgsStayHardened(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI is not available")
	}
	args := CreateArgs(ExecutorSpec{
		Name:           "cloud-harness-ws-paritytest",
		Image:          "cloud-harness-executor:local",
		WorkspaceID:    "ws_abcdefghijklmnopqrst",
		InstanceID:     "parity",
		RepositoryPath: "/jobs/ws/repo",
		Network:        protocol.NetworkNone,
	})
	if err := ValidateCreateArgs(args); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--network bridge") {
		t.Fatalf("unsafe live docker args: %s", joined)
	}
	_ = context.Background()
}
