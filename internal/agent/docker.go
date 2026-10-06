package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// DockerInvoker is the runner Docker CLI used for per-agent isolation.
type DockerInvoker interface {
	Invoke(ctx context.Context, args []string, stdin string) (sandbox.Result, error)
}

// DockerSpawner starts a long-lived `docker run -i` for the JSONL protocol.
type DockerSpawner interface {
	Spawn(args []string, extraEnv []string) (*exec.Cmd, error)
}

// Launcher creates an internal per-agent network and a no-mount container.
// Provider secrets, docker.sock, and host/repo mounts never appear on argv.
type Launcher struct {
	Docker     DockerInvoker
	Spawn      DockerSpawner
	InstanceID string
	Image      string
	GatewayURL string
	GatewayCtr string
}

// LaunchResult is the isolation identity of a started (or attempted) agent.
type LaunchResult struct {
	ContainerName string
	NetworkName   string
	Channel       *Channel
	Wait          func() error
}

func (l *Launcher) names(agentID string) (container, network string) {
	sum := sha256.Sum256([]byte(agentID))
	suffix := hex.EncodeToString(sum[:])[:20]
	return "ch-agent-" + suffix, "ch-agent-net-" + suffix
}

func (l *Launcher) spec(agentID, workspaceID string, generation int) LaunchSpec {
	container, network := l.names(agentID)
	return LaunchSpec{
		ContainerName: container,
		NetworkName:   network,
		Image:         l.Image,
		AgentID:       agentID,
		WorkspaceID:   workspaceID,
		Generation:    generation,
		InstanceID:    l.InstanceID,
		GatewayURL:    l.GatewayURL,
	}
}

// Launch creates the internal network, optionally attaches the gateway, then
// `docker run`s the agent image. Failure always attempts cleanup.
func (l *Launcher) Launch(ctx context.Context, agentID, workspaceID string, generation int) (LaunchResult, error) {
	spec := l.spec(agentID, workspaceID, generation)
	out := LaunchResult{ContainerName: spec.ContainerName, NetworkName: spec.NetworkName}
	if l.Docker == nil {
		return out, fmt.Errorf("%s: agent docker launcher is not configured", protocol.ErrorUnavailable)
	}
	if l.Image == "" || l.GatewayURL == "" {
		return out, fmt.Errorf("%s: agent launch spec is incomplete", protocol.ErrorUnavailable)
	}
	args, err := RunArgs(spec)
	if err != nil {
		return out, err
	}
	if err := ValidateRunArgs(args); err != nil {
		return out, err
	}
	if res, err := l.Docker.Invoke(ctx, NetworkCreateArgs(spec), ""); err != nil {
		return out, err
	} else if res.ExitCode != 0 {
		return out, fmt.Errorf("%s: agent network creation failed", protocol.ErrorUnavailable)
	}
	if l.GatewayCtr != "" {
		connect := []string{"network", "connect", "--alias", "model-gateway", spec.NetworkName, l.GatewayCtr}
		if res, err := l.Docker.Invoke(ctx, connect, ""); err != nil || res.ExitCode != 0 {
			_ = l.Cleanup(ctx, out)
			return out, fmt.Errorf("%s: model gateway could not join the agent network", protocol.ErrorUnavailable)
		}
	}
	if l.Spawn != nil {
		cmd, err := l.Spawn.Spawn(args, nil)
		if err != nil {
			_ = l.Cleanup(ctx, out)
			return out, err
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			_ = l.Cleanup(ctx, out)
			return out, err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			_ = l.Cleanup(ctx, out)
			return out, err
		}
		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			_ = l.Cleanup(ctx, out)
			return out, err
		}
		out.Channel = NewChannel(stdin, stdout)
		out.Wait = cmd.Wait
		return out, nil
	}
	if res, err := l.Docker.Invoke(ctx, args, ""); err != nil {
		_ = l.Cleanup(ctx, out)
		return out, err
	} else if res.ExitCode != 0 {
		_ = l.Cleanup(ctx, out)
		return out, fmt.Errorf("%s: agent container launch failed", protocol.ErrorUnavailable)
	}
	return out, nil
}

// Cleanup force-removes the agent container and its private network.
func (l *Launcher) Cleanup(ctx context.Context, ids LaunchResult) error {
	if l.Docker == nil {
		return nil
	}
	if ids.ContainerName != "" {
		_, _ = l.Docker.Invoke(ctx, []string{"rm", "--force", ids.ContainerName}, "")
	}
	if ids.NetworkName != "" && l.GatewayCtr != "" {
		_, _ = l.Docker.Invoke(ctx, []string{"network", "disconnect", "--force", ids.NetworkName, l.GatewayCtr}, "")
	}
	if ids.NetworkName != "" {
		if res, err := l.Docker.Invoke(ctx, []string{"network", "rm", ids.NetworkName}, ""); err != nil {
			return err
		} else if res.ExitCode != 0 && !strings.Contains(strings.ToLower(res.Stderr), "no such network") {
			return fmt.Errorf("%s: agent network removal failed", protocol.ErrorUnavailable)
		}
	}
	return nil
}
