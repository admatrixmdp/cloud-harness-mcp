package sandbox

import (
	"context"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestCreateExecutorRejectsSocket(t *testing.T) {
	eng := Engine{Image: "cloud-harness-executor:local", InstanceID: "inst"}
	spec := ExecutorSpec{
		Name:           "cloud-harness-ws-test",
		WorkspaceID:    "ws_abcdefghijklmnopqrst",
		RepositoryPath: "/var/run/docker.sock",
		Network:        protocol.NetworkNone,
		Image:          eng.Image,
		InstanceID:     eng.InstanceID,
	}
	args := CreateArgs(spec)
	if err := ValidateCreateArgs(args); err == nil {
		t.Fatal("docker.sock volume must be rejected")
	}
}

func TestCreateExecutorUsesPolicy(t *testing.T) {
	var got []string
	eng := Engine{
		Image:      "cloud-harness-executor:local",
		InstanceID: "inst",
		Run: func(_ context.Context, args []string, stdin string) (Result, error) {
			got = append([]string{}, args...)
			if stdin != "" {
				t.Fatal("create must not send a token on stdin")
			}
			return Result{ExitCode: 0}, nil
		},
	}
	name, err := eng.CreateExecutor(context.Background(), ExecutorSpec{
		Name:           "cloud-harness-ws-test",
		WorkspaceID:    "ws_abcdefghijklmnopqrst",
		RepositoryPath: "/jobs/ws/repo",
		Network:        protocol.NetworkNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if name != "cloud-harness-ws-test" {
		t.Fatalf("name %s", name)
	}
	if err := ValidateCreateArgs(got); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--network bridge") {
		t.Fatalf("unsafe args: %s", joined)
	}
}

func TestHelperStdin(t *testing.T) {
	if HelperStdin("") != "\n" {
		t.Fatal("empty token still sends newline")
	}
	if HelperStdin("ghs_x") != "ghs_x\n" {
		t.Fatal("token must be one stdin line")
	}
}
