package agent

import (
	"fmt"
	"strings"
)

// LaunchSpec is the isolation policy for one ephemeral subagent container.
type LaunchSpec struct {
	ContainerName string
	NetworkName   string
	Image         string
	AgentID       string
	WorkspaceID   string
	Generation    int
	InstanceID    string
	GatewayURL    string
}

// RunArgs is the docker run argv for a subagent. No host/repo mounts, no
// provider secrets, no docker.sock — only the opaque gateway URL.
func RunArgs(spec LaunchSpec) ([]string, error) {
	if spec.ContainerName == "" || spec.NetworkName == "" || spec.Image == "" {
		return nil, fmt.Errorf("agent launch spec is incomplete")
	}
	if !ValidAgentID(spec.AgentID) {
		return nil, fmt.Errorf("agentId is invalid")
	}
	if strings.Contains(spec.GatewayURL, "sk-") || strings.Contains(strings.ToLower(spec.GatewayURL), "api-key") {
		return nil, fmt.Errorf("gateway URL must not carry provider credentials")
	}
	alias := spec.AgentID
	if len(alias) > 12 {
		alias = alias[len(alias)-12:]
	}
	return []string{
		"run", "--interactive", "--pull", "never",
		"--name", spec.ContainerName,
		"--label", "cloud-harness.agent-container=true",
		"--label", "cloud-harness.instance=" + spec.InstanceID,
		"--label", "cloud-harness.workspace=" + spec.WorkspaceID,
		"--label", fmt.Sprintf("cloud-harness.agent-generation=%d", spec.Generation),
		"--label", "cloud-harness.agent=" + spec.AgentID,
		"--network", spec.NetworkName,
		"--network-alias", "agent-" + alias,
		"--user", "10001:10001",
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "256",
		"--memory", "1g",
		"--memory-swap", "1g",
		"--cpus", "1",
		"--env", "AGENT_MODEL_GATEWAY_URL=" + strings.TrimRight(spec.GatewayURL, "/") + "/v1",
		"--env", "HOME=/tmp",
		spec.Image,
	}, nil
}

// NetworkCreateArgs builds an internal per-agent bridge. Production must not
// use a shared static agent network.
func NetworkCreateArgs(spec LaunchSpec) []string {
	return []string{
		"network", "create", "--internal", "--driver", "bridge",
		"--label", "cloud-harness.agent-network=true",
		"--label", "cloud-harness.instance=" + spec.InstanceID,
		"--label", "cloud-harness.workspace=" + spec.WorkspaceID,
		"--label", "cloud-harness.agent=" + spec.AgentID,
		spec.NetworkName,
	}
}

// ValidateRunArgs rejects host mounts, docker.sock, and secret env.
func ValidateRunArgs(args []string) error {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "docker.sock") {
		return fmt.Errorf("agent container must not receive the Docker socket")
	}
	if strings.Contains(joined, "--volume") || strings.Contains(joined, " -v ") || hasFlag(args, "-v") || hasFlag(args, "--volume") {
		return fmt.Errorf("agent container must not receive host or repository mounts")
	}
	if strings.Contains(joined, "--mount") || hasFlag(args, "--mount") {
		return fmt.Errorf("agent container must not receive host or repository mounts")
	}
	for i, arg := range args {
		if arg == "-e" || arg == "--env" {
			if i+1 >= len(args) {
				return fmt.Errorf("dangling --env")
			}
			env := args[i+1]
			name, _, _ := strings.Cut(env, "=")
			upper := strings.ToUpper(name)
			if strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "API_KEY") || upper == "OPENAI_API_KEY" {
				return fmt.Errorf("agent container must not receive provider secrets")
			}
		}
	}
	if !contains(args, "--cap-drop") || !contains(args, "ALL") {
		return fmt.Errorf("agent container must drop all capabilities")
	}
	if !contains(args, "--read-only") {
		return fmt.Errorf("agent container must be read-only")
	}
	return nil
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

func contains(args []string, needle string) bool {
	for _, a := range args {
		if a == needle {
			return true
		}
	}
	return false
}
