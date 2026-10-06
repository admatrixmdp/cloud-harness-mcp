//go:build docker

package runner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func dockerBin(t *testing.T) string {
	t.Helper()
	if bin, err := exec.LookPath("docker"); err == nil {
		return bin
	}
	if _, err := os.Stat("/usr/local/bin/docker"); err == nil {
		return "/usr/local/bin/docker"
	}
	t.Skip("docker CLI is not available")
	return ""
}

func TestLiveWorkspaceOpenStartsExecutorAndRunsWorker(t *testing.T) {
	docker := dockerBin(t)
	if dir := filepath.Dir(docker); dir != "" && dir != "." {
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	if out, err := exec.Command(docker, "image", "inspect", "cloud-harness-executor:local").CombinedOutput(); err != nil {
		t.Skipf("cloud-harness-executor:local is not available: %s", strings.TrimSpace(string(out)))
	}

	jobsRoot := t.TempDir()
	engine := &sandbox.Engine{Image: "cloud-harness-executor:local", InstanceID: "go-live-open"}
	svc := NewService(Config{
		NetworkProfile:  protocol.NetworkNone,
		JobsRoot:        jobsRoot,
		ExecutorImage:   "cloud-harness-executor:local",
		InstanceID:      "go-live-open",
		AllowedGitHosts: []string{"github.com"},
	}, nil, DockerEngine{Inner: engine, JobsRoot: jobsRoot}).WithDocker(engine)

	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version:   2,
		OwnerID:   "owner",
		Operation: protocol.OpWorkspaceOpen,
		Input:     json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"go-live-open-001","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	data, _ := open.Data.(map[string]any)
	workspaceID, _ := data["workspaceId"].(string)
	if workspaceID == "" {
		t.Fatalf("open payload %+v", open.Data)
	}
	containerName := containerName(workspaceID)
	t.Cleanup(func() {
		_ = svc.Execute(context.Background(), protocol.RunnerRequest{
			Version:   2,
			OwnerID:   "owner",
			Operation: protocol.OpWorkspaceClose,
			Input:     json.RawMessage(`{"workspaceId":"` + workspaceID + `"}`),
		})
		_ = exec.Command(docker, "rm", "--force", containerName).Run()
	})

	inspectRaw, err := exec.Command(docker, "inspect", "--format", "{{.State.Running}} {{.HostConfig.NetworkMode}} {{.Config.User}}", containerName).Output()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	got := strings.TrimSpace(string(inspectRaw))
	if !strings.HasPrefix(got, "true none 10001:10001") {
		t.Fatalf("executor must be running, network-none, UID 10001: %q", got)
	}

	write := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version:   2,
		OwnerID:   "owner",
		Operation: protocol.OpFilesWrite,
		Input:     json.RawMessage(`{"workspaceId":"` + workspaceID + `","path":"from-open.txt","content":"started"}`),
	})
	if !write.OK {
		t.Fatalf("files_write: %+v", write)
	}
	hostCopy, err := os.ReadFile(filepath.Join(jobsRoot, workspaceID, "repo", "from-open.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hostCopy), "started") {
		t.Fatalf("host workspace %q", hostCopy)
	}
}
