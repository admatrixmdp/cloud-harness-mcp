package sandbox

import (
	"context"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

type staticAttestor struct {
	ok     bool
	reason string
	err    error
}

func (s staticAttestor) Verify(context.Context) (bool, string, error) {
	return s.ok, s.reason, s.err
}

func TestCreateArgsNeverMountSocketOrBridge(t *testing.T) {
	args := CreateArgs(ExecutorSpec{
		Name:           "cloud-harness-ws-test",
		Image:          "cloud-harness-executor:local",
		WorkspaceID:    "ws_abcdefghijklmnopqrst",
		InstanceID:     "inst",
		RepositoryPath: "/jobs/ws/repo",
		Network:        protocol.NetworkNone,
	})
	if err := ValidateCreateArgs(args); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "docker.sock") {
		t.Fatal("docker.sock leaked into create args")
	}
	if strings.Contains(joined, "--network bridge") {
		t.Fatal("raw bridge selected")
	}
	if !strings.Contains(joined, "--network none") {
		t.Fatalf("network-none args: %s", joined)
	}
	if !strings.Contains(joined, "--user 10001:10001") {
		t.Fatal("executor must be non-root")
	}
}

func TestDependencyAccessArgs(t *testing.T) {
	args := NetworkArgs(protocol.DependencyAccess, "", nil)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, DefaultDependencyNet) {
		t.Fatalf("got %s", joined)
	}
	if strings.Contains(joined, "bridge") {
		t.Fatal("bridge must not appear")
	}
}

func TestAttestationFailClosed(t *testing.T) {
	err := EnsureProfileReady(context.Background(), protocol.DependencyAccess, nil)
	if err == nil || !strings.Contains(err.Error(), string(protocol.ErrorDependencyEgressUnavailable)) {
		t.Fatalf("nil attestor: %v", err)
	}
	err = EnsureProfileReady(context.Background(), protocol.DependencyAccess, staticAttestor{ok: false, reason: "ipv6 enabled"})
	if err == nil || !strings.Contains(err.Error(), "ipv6") {
		t.Fatalf("failed attestation: %v", err)
	}
	if err := EnsureProfileReady(context.Background(), protocol.NetworkNone, nil); err != nil {
		t.Fatal(err)
	}
	if err := EnsureProfileReady(context.Background(), protocol.DependencyAccess, staticAttestor{ok: true}); err != nil {
		t.Fatal(err)
	}
}

func TestBridgeRejected(t *testing.T) {
	if err := EnsureProfileReady(context.Background(), protocol.NetworkProfile("bridge"), nil); err == nil {
		t.Fatal("bridge must be rejected")
	}
}

func TestSkillHelperArgsUnprivilegedNoSocket(t *testing.T) {
	args := SkillHelperArgs(SkillHelperSpec{
		Name:           "chm-skill-test",
		Image:          "cloud-harness-executor:local",
		InstanceID:     "inst",
		WorkspaceID:    "ws_abcdefghijklmnopqrst",
		RepositoryPath: "/jobs/ws/repo",
		ToolsPath:      "/jobs/ws/tools",
		CachePath:      "/jobs/ws/cache",
		Network:        protocol.NetworkNone,
	})
	if err := ValidateSkillHelperArgs(args); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "docker.sock") {
		t.Fatal("docker.sock leaked")
	}
	if strings.Contains(joined, "--network bridge") {
		t.Fatal("raw bridge selected")
	}
	if !strings.Contains(joined, "--user 10001:10001") {
		t.Fatal("skill helper must be non-root")
	}
	if !strings.Contains(joined, "--network none") {
		t.Fatalf("network-none helper: %s", joined)
	}
	if !strings.Contains(joined, "/opt/harness/harness-worker") {
		t.Fatal("missing Go worker entrypoint")
	}
	if strings.Contains(joined, "GH_TOKEN=") || strings.Contains(joined, "GITHUB_TOKEN=") {
		t.Fatal("token in argv")
	}
	leaky := append([]string{}, args...)
	leaky = append(leaky, "--volume", "/var/run/docker.sock:/var/run/docker.sock")
	if err := ValidateSkillHelperArgs(leaky); err == nil {
		t.Fatal("socket mount must be rejected")
	}
}
