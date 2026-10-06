package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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

func TestWorkerExecArgsAreUnprivilegedStdinOnly(t *testing.T) {
	args := WorkerExecArgs("cloud-harness-ws-test", "op_abcdefghijklmnopqrstuvwx")
	if err := ValidateWorkerExecArgs(args); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--privileged") {
		t.Fatalf("leaky exec: %s", joined)
	}
	if strings.Contains(joined, "GH_TOKEN=") {
		t.Fatal("token in argv")
	}
	if args[0] != "exec" || args[1] != "-i" {
		t.Fatalf("must be docker exec -i: %v", args)
	}
	leaky := append([]string{}, args...)
	leaky = append(leaky, "--privileged")
	if err := ValidateWorkerExecArgs(leaky); err == nil {
		t.Fatal("privileged exec must be rejected")
	}
}

func TestGoExecutorDockerfileOwnsWorkerBinary(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if err := OverlayExecutorImageOwnsGoWorker(filepath.Join(root, "docker", "go-executor.Dockerfile")); err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(root, "worker", "worker-runner.go.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "exec /opt/harness/harness-worker") {
		t.Fatal("overlay runner must exec the Go worker")
	}
	if strings.Contains(string(script), "harness-worker.mjs") {
		t.Fatal("overlay runner must not invoke the TypeScript worker")
	}
	shipped, err := os.ReadFile(filepath.Join(root, "worker", "worker-runner.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(shipped), "node /opt/harness/harness-worker.mjs") {
		t.Fatal("shipped TypeScript worker-runner.sh must keep the Node entry")
	}
}

func TestInteractiveAndTaskExecArgsStayUnprivileged(t *testing.T) {
	shell := InteractiveExecArgs("cloud-harness-ws-test", "src", "sess_abcdefghijklmnopqrstuvwx")
	if err := ValidateInteractiveExecArgs(shell); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(shell, " ")
	if !strings.Contains(joined, "-w") || !strings.Contains(joined, "/workspace/src") {
		t.Fatalf("workdir: %s", joined)
	}
	if !strings.Contains(joined, "shell-runner.sh") || strings.Contains(joined, "worker-runner.sh") {
		t.Fatalf("session must not use one-shot worker: %s", joined)
	}
	task := TaskExecArgs("cloud-harness-ws-test", ".", "task_abcdefghijklmnopqrstuvwx", 30)
	if err := ValidateTaskExecArgs(task); err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(task, " ")
	if strings.Contains(joined, "CH_COMMAND=") {
		t.Fatal("task command must not appear in argv")
	}
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--privileged") {
		t.Fatalf("leaky task exec: %s", joined)
	}
}
