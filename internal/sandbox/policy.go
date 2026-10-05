package sandbox

import (
	"context"
	"fmt"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	ExecutorUser         = "10001:10001"
	ExecutorWorkdir      = "/workspace"
	DefaultDependencyNet = "cloud-harness-dependency-access"
	DefaultPidsLimit     = "256"
	DefaultMemory        = "1g"
	DefaultCPUs          = "1"
	ManagedLabel         = "cloud-harness.managed=true"
)

// ExecutorSpec is the structured Docker create policy for a workspace executor.
type ExecutorSpec struct {
	Name            string
	Image           string
	WorkspaceID     string
	InstanceID      string
	RepositoryPath  string
	ToolsPath       string
	CachePath       string
	OwnerSkillsPath string
	Network         protocol.NetworkProfile
	DependencyNet   string
	DNSResolvers    []string
}

// Attestor verifies the host firewall for dependency-access.
type Attestor interface {
	Verify(ctx context.Context) (ok bool, reason string, err error)
}

// EnsureProfileReady is fail-closed: attestation failure never silently
// downgrades to network-none or raw bridge.
func EnsureProfileReady(ctx context.Context, profile protocol.NetworkProfile, attestor Attestor) error {
	if !profile.Valid() {
		return fmt.Errorf("%s: network profile %q is not selectable", protocol.ErrorInvalidInput, profile)
	}
	if profile == protocol.NetworkNone {
		return nil
	}
	if attestor == nil {
		return fmt.Errorf("%s: dependency-access egress profile is unavailable: attestation not configured", protocol.ErrorDependencyEgressUnavailable)
	}
	ok, reason, err := attestor.Verify(ctx)
	if err != nil {
		return fmt.Errorf("%s: dependency-access egress profile is unavailable: %v", protocol.ErrorDependencyEgressUnavailable, err)
	}
	if !ok {
		if reason == "" {
			reason = "verification failed"
		}
		return fmt.Errorf("%s: dependency-access egress profile is unavailable: %s", protocol.ErrorDependencyEgressUnavailable, reason)
	}
	return nil
}

// NetworkArgs returns docker network flags for a shipped profile.
func NetworkArgs(profile protocol.NetworkProfile, dependencyNet string, dns []string) []string {
	if profile == protocol.NetworkNone {
		return []string{"--network", "none"}
	}
	if dependencyNet == "" {
		dependencyNet = DefaultDependencyNet
	}
	if len(dns) == 0 {
		dns = []string{"8.8.8.8", "1.1.1.1"}
	}
	args := []string{"--network", dependencyNet}
	for _, resolver := range dns {
		args = append(args, "--dns", resolver)
	}
	args = append(args, "--label", "cloud-harness.network-profile=dependency-access")
	return args
}

// CreateArgs is the docker create argv for a workspace executor.
// It never mounts the Docker socket and never selects raw bridge.
func CreateArgs(spec ExecutorSpec) []string {
	netName := spec.DependencyNet
	args := []string{
		"create", "--name", spec.Name,
		"--label", ManagedLabel,
		"--label", "cloud-harness.instance=" + spec.InstanceID,
		"--label", "cloud-harness.workspace=" + spec.WorkspaceID,
		"--user", ExecutorUser,
		"--workdir", ExecutorWorkdir,
		"--read-only",
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=128m",
		"--tmpfs", "/run:rw,nosuid,nodev,size=8m",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", DefaultPidsLimit,
		"--memory", DefaultMemory,
		"--memory-swap", DefaultMemory,
		"--cpus", DefaultCPUs,
		"--ulimit", "nofile=1024:1024",
	}
	args = append(args, NetworkArgs(spec.Network, netName, spec.DNSResolvers)...)
	if spec.RepositoryPath != "" {
		args = append(args, "--volume", spec.RepositoryPath+":/workspace:rw")
	}
	if spec.ToolsPath != "" {
		args = append(args, "--volume", spec.ToolsPath+":/opt/user-tools:rw")
	}
	if spec.CachePath != "" {
		args = append(args, "--volume", spec.CachePath+":/var/cache/harness:rw")
	}
	if spec.OwnerSkillsPath != "" {
		args = append(args, "--volume", spec.OwnerSkillsPath+":/opt/cloud-harness/owner-skills:ro")
	}
	args = append(args,
		"--env", "HOME=/tmp/cloud-harness-home",
		"--env", "GIT_CONFIG_NOSYSTEM=1",
		spec.Image,
	)
	return args
}

// ForbiddenVolume reports whether a docker volume mapping leaks the Docker socket
// or a control-plane credential path into the executor.
func ForbiddenVolume(mapping string) bool {
	lower := strings.ToLower(mapping)
	if strings.Contains(lower, "docker.sock") {
		return true
	}
	if strings.Contains(lower, "/var/run/docker.sock") {
		return true
	}
	return false
}

// ValidateCreateArgs rejects raw bridge, docker.sock, and missing hardening flags.
func ValidateCreateArgs(args []string) error {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--network bridge") {
		return fmt.Errorf("raw bridge profile is not selectable")
	}
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--volume" && ForbiddenVolume(args[i+1]) {
			return fmt.Errorf("docker socket must not be mounted into an executor")
		}
	}
	required := []string{"--read-only", "--cap-drop", "--security-opt", "--user"}
	for _, flag := range required {
		if !contains(args, flag) {
			return fmt.Errorf("missing required hardening flag %s", flag)
		}
	}
	return nil
}

func contains(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
