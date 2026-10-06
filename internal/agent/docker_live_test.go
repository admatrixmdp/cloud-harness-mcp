//go:build docker

package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

func TestLiveAgentImageHasNoMountsOrSecrets(t *testing.T) {
	docker := dockerBin(t)
	if out, err := exec.Command(docker, "image", "inspect", "cloud-harness-agent:local").CombinedOutput(); err != nil {
		t.Skipf("cloud-harness-agent:local is not available: %s", strings.TrimSpace(string(out)))
	}

	suffix := strings.ReplaceAll(filepath.Base(t.TempDir()), " ", "")
	spec := LaunchSpec{
		ContainerName: "ch-agent-go-live-" + suffix,
		NetworkName:   "ch-agent-net-go-live-" + suffix,
		Image:         "cloud-harness-agent:local",
		AgentID:       "agent_abcdefghijklmnopqrstuvwx",
		WorkspaceID:   "ws_abcdefghijklmnopqrstuvwx",
		Generation:    1,
		InstanceID:    "go-live",
		GatewayURL:    "http://model-gateway:3210",
	}
	runArgs, err := RunArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRunArgs(runArgs); err != nil {
		t.Fatal(err)
	}

	netArgs := NetworkCreateArgs(spec)
	if out, err := exec.Command(docker, netArgs...).CombinedOutput(); err != nil {
		t.Fatalf("network create: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command(docker, "rm", "--force", spec.ContainerName).Run()
		_ = exec.Command(docker, "network", "rm", spec.NetworkName).Run()
	})

	// Distroless keepalive: --hold instead of sleep. Detach so inspect can run.
	cmdArgs := append([]string{"run", "--detach"}, runArgs[1:]...)
	cmdArgs = append(cmdArgs, "--hold")
	if out, err := exec.Command(docker, cmdArgs...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}

	raw, err := exec.Command(docker, "inspect", spec.ContainerName).Output()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	var reports []struct {
		Config struct {
			User string
			Env  []string
			Cmd  []string
		}
		HostConfig struct {
			ReadonlyRootfs bool
			CapDrop        []string
			SecurityOpt    []string
			PidsLimit      int64
			Memory         int64
			Binds          []string
			Mounts         []any
		}
		Mounts []struct {
			Source      string
			Destination string
		}
		NetworkSettings struct {
			Networks map[string]any
		}
	}
	if err := json.Unmarshal(raw, &reports); err != nil || len(reports) != 1 {
		t.Fatalf("inspect json: %v body=%s", err, raw)
	}
	got := reports[0]
	if got.Config.User != "10001:10001" {
		t.Fatalf("user %q", got.Config.User)
	}
	if !got.HostConfig.ReadonlyRootfs {
		t.Fatal("rootfs must be read-only")
	}
	if !contains(got.HostConfig.CapDrop, "ALL") {
		t.Fatalf("cap-drop %v", got.HostConfig.CapDrop)
	}
	if len(got.Mounts) != 0 {
		t.Fatalf("agent must not receive mounts: %+v", got.Mounts)
	}
	if len(got.HostConfig.Binds) != 0 {
		t.Fatalf("agent must not receive binds: %v", got.HostConfig.Binds)
	}
	joinedEnv := strings.Join(got.Config.Env, "\n")
	if strings.Contains(strings.ToLower(joinedEnv), "token") || strings.Contains(strings.ToLower(joinedEnv), "secret") || strings.Contains(joinedEnv, "sk-") {
		t.Fatalf("agent env leaked credentials: %s", joinedEnv)
	}
	if !strings.Contains(joinedEnv, "AGENT_MODEL_GATEWAY_URL=http://model-gateway:3210/v1") {
		t.Fatalf("gateway URL missing: %s", joinedEnv)
	}
	if _, ok := got.NetworkSettings.Networks[spec.NetworkName]; !ok {
		t.Fatalf("networks %v", got.NetworkSettings.Networks)
	}
	if len(got.NetworkSettings.Networks) != 1 {
		t.Fatalf("agent must join only its internal network: %v", got.NetworkSettings.Networks)
	}

	netRaw, err := exec.Command(docker, "network", "inspect", spec.NetworkName).Output()
	if err != nil {
		t.Fatalf("network inspect: %v", err)
	}
	var nets []struct {
		Internal bool
		Options  map[string]string
	}
	if err := json.Unmarshal(netRaw, &nets); err != nil || len(nets) != 1 {
		t.Fatalf("network json: %v", err)
	}
	if !nets[0].Internal {
		t.Fatal("agent network must be internal")
	}
}
