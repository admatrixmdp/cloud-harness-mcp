package agent

import (
	"strings"
	"testing"
)

func TestRunArgsRejectsSecretsAndMounts(t *testing.T) {
	spec := LaunchSpec{
		ContainerName: "ch-agent-abc",
		NetworkName:   "ch-agent-net-abc",
		Image:         "cloud-harness-agent:local",
		AgentID:       "agent_" + strings.Repeat("c", 24),
		WorkspaceID:   "ws_abcdefghijklmnopqrstuvwx",
		InstanceID:    "local",
		GatewayURL:    "http://model-gateway:3210",
	}
	args, err := RunArgs(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRunArgs(args); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--volume") {
		t.Fatalf("mount leaked: %s", joined)
	}
	if strings.Contains(joined, "OPENAI") || strings.Contains(joined, "sk-") {
		t.Fatalf("secret leaked: %s", joined)
	}
	if !strings.Contains(joined, "--network "+spec.NetworkName) {
		t.Fatalf("missing per-agent network: %s", joined)
	}
	net := NetworkCreateArgs(spec)
	if !strings.Contains(strings.Join(net, " "), "--internal") {
		t.Fatal("agent network must be internal")
	}
	bad := append([]string{}, args...)
	bad = append(bad, "--volume", "/var/run/docker.sock:/var/run/docker.sock")
	if err := ValidateRunArgs(bad); err == nil {
		t.Fatal("docker.sock must be rejected")
	}
	secreted := append([]string{}, args...)
	secreted = append(secreted, "--env", "OPENAI_API_KEY=sk-test")
	if err := ValidateRunArgs(secreted); err == nil {
		t.Fatal("provider secret env must be rejected")
	}
}

func TestRunArgsRejectsCredentialInURL(t *testing.T) {
	_, err := RunArgs(LaunchSpec{
		ContainerName: "c", NetworkName: "n", Image: "img",
		AgentID: "agent_" + strings.Repeat("d", 24), GatewayURL: "http://x/sk-live",
	})
	if err == nil {
		t.Fatal("credential-looking URL accepted")
	}
}
