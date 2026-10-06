//go:build docker

package sandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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

func requireImage(t *testing.T, docker, image string) {
	t.Helper()
	cmd := exec.Command(docker, "image", "inspect", image)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("%s is not available: %s", image, strings.TrimSpace(string(out)))
	}
}

func TestLiveExecutorImageMatchesIsolationPolicy(t *testing.T) {
	docker := dockerBin(t)
	requireImage(t, docker, "cloud-harness-executor:local")

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "seed.txt"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	name := "cloud-harness-ws-go-live-" + strings.ReplaceAll(filepath.Base(root), " ", "")
	spec := ExecutorSpec{
		Name:           name,
		Image:          "cloud-harness-executor:local",
		WorkspaceID:    "ws_abcdefghijklmnopqrst",
		InstanceID:     "go-live",
		RepositoryPath: repo,
		Network:        protocol.NetworkNone,
	}
	args := CreateArgs(spec)
	if err := ValidateCreateArgs(args); err != nil {
		t.Fatal(err)
	}

	create := exec.Command(docker, args...)
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("docker create: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command(docker, "rm", "--force", name).Run()
	})

	if out, err := exec.Command(docker, "start", name).CombinedOutput(); err != nil {
		t.Fatalf("docker start: %v\n%s", err, out)
	}

	inspect := exec.Command(docker, "inspect", name)
	raw, err := inspect.Output()
	if err != nil {
		t.Fatalf("docker inspect: %v", err)
	}
	var reports []struct {
		Config struct {
			User  string
			Env   []string
			Image string
		}
		HostConfig struct {
			ReadonlyRootfs bool
			NetworkMode    string
			CapDrop        []string
			SecurityOpt    []string
			PidsLimit      int64
			Memory         int64
			MemorySwap     int64
			NanoCpus       int64
			Binds          []string
		}
		Mounts []struct {
			Source      string
			Destination string
		}
	}
	if err := json.Unmarshal(raw, &reports); err != nil || len(reports) != 1 {
		t.Fatalf("inspect json: %v body=%s", err, raw)
	}
	got := reports[0]
	if got.Config.User != ExecutorUser {
		t.Fatalf("user %q", got.Config.User)
	}
	if !got.HostConfig.ReadonlyRootfs {
		t.Fatal("rootfs must be read-only")
	}
	if got.HostConfig.NetworkMode != "none" {
		t.Fatalf("network %q", got.HostConfig.NetworkMode)
	}
	if !contains(got.HostConfig.CapDrop, "ALL") {
		t.Fatalf("cap-drop %v", got.HostConfig.CapDrop)
	}
	if !contains(got.HostConfig.SecurityOpt, "no-new-privileges") && !contains(got.HostConfig.SecurityOpt, "no-new-privileges:true") {
		t.Fatalf("security-opt %v", got.HostConfig.SecurityOpt)
	}
	if got.HostConfig.PidsLimit != 256 {
		t.Fatalf("pids %d", got.HostConfig.PidsLimit)
	}
	if got.HostConfig.Memory != 1_073_741_824 {
		t.Fatalf("memory %d", got.HostConfig.Memory)
	}
	joinedEnv := strings.Join(got.Config.Env, "\n")
	if strings.Contains(strings.ToLower(joinedEnv), "token") || strings.Contains(strings.ToLower(joinedEnv), "secret") {
		t.Fatalf("executor env leaked credentials: %s", joinedEnv)
	}
	for _, bind := range got.HostConfig.Binds {
		if ForbiddenVolume(bind) {
			t.Fatalf("forbidden bind %s", bind)
		}
	}
	for _, mount := range got.Mounts {
		if ForbiddenVolume(mount.Source) || ForbiddenVolume(mount.Destination) {
			t.Fatalf("forbidden mount %+v", mount)
		}
	}

	write := exec.Command(docker, WorkerExecArgs(name, "op_livewrite")...)
	write.Stdin = strings.NewReader(`{"operation":"files_write","input":{"path":"hello.txt","content":"from-go-worker"}}`)
	var writeOut bytes.Buffer
	write.Stdout = &writeOut
	write.Stderr = &writeOut
	if err := write.Run(); err != nil {
		t.Fatalf("files_write: %v\n%s", err, writeOut.String())
	}
	var writeRes protocol.ToolResult
	if err := json.Unmarshal(writeOut.Bytes(), &writeRes); err != nil {
		t.Fatalf("files_write json %q: %v", writeOut.String(), err)
	}
	if !writeRes.OK {
		t.Fatalf("files_write: %+v", writeRes)
	}

	read := exec.Command(docker, WorkerExecArgs(name, "op_liveread")...)
	read.Stdin = strings.NewReader(`{"operation":"files_read","input":{"path":"hello.txt"}}`)
	var readOut bytes.Buffer
	read.Stdout = &readOut
	read.Stderr = &readOut
	if err := read.Run(); err != nil {
		t.Fatalf("files_read: %v\n%s", err, readOut.String())
	}
	var readRes protocol.ToolResult
	if err := json.Unmarshal(readOut.Bytes(), &readRes); err != nil {
		t.Fatalf("files_read json %q: %v", readOut.String(), err)
	}
	if !readRes.OK {
		t.Fatalf("files_read: %+v", readRes)
	}
	data, _ := readRes.Data.(map[string]any)
	content, _ := data["content"].(string)
	if !strings.Contains(content, "from-go-worker") {
		t.Fatalf("content %v", readRes.Data)
	}

	hostCopy, err := os.ReadFile(filepath.Join(repo, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(hostCopy, []byte("from-go-worker")) {
		t.Fatalf("host workspace was not updated: %q", hostCopy)
	}

	escape := exec.Command(docker, WorkerExecArgs(name, "op_liveescape")...)
	escape.Stdin = strings.NewReader(`{"operation":"files_read","input":{"path":"../etc/passwd"}}`)
	var escapeOut bytes.Buffer
	escape.Stdout = &escapeOut
	escape.Stderr = &escapeOut
	if err := escape.Run(); err != nil {
		t.Fatalf("escape files_read: %v\n%s", err, escapeOut.String())
	}
	var escapeRes protocol.ToolResult
	if err := json.Unmarshal(escapeOut.Bytes(), &escapeRes); err != nil {
		t.Fatalf("escape json %q: %v", escapeOut.String(), err)
	}
	if escapeRes.OK || escapeRes.Error == nil || escapeRes.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("path escape must fail closed: %+v", escapeRes)
	}
}
