package sandbox

import (
	"context"
	"fmt"
	"os"
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

// SkillHelperSpec is a disposable unprivileged helper for skills_run.
// Repository-controlled scripts never run as root and never see the Docker socket.
type SkillHelperSpec struct {
	Name           string
	Image          string
	InstanceID     string
	WorkspaceID    string
	RepositoryPath string
	ToolsPath      string
	CachePath      string
	Network        protocol.NetworkProfile
	DependencyNet  string
	DNSResolvers   []string
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

// SkillHelperArgs is docker run argv for a grant-gated skills_run helper.
// The worker payload rides stdin; argv never includes tokens or docker.sock.
func SkillHelperArgs(spec SkillHelperSpec) []string {
	args := []string{
		"run", "-i", "--rm", "--pull", "never", "--name", spec.Name,
		"--label", ManagedLabel,
		"--label", "cloud-harness.instance=" + spec.InstanceID,
		"--label", "cloud-harness.workspace=" + spec.WorkspaceID,
		"--label", "cloud-harness.role=skill-helper",
		"--label", "cloud-harness.ephemeral=true",
	}
	args = append(args, NetworkArgs(spec.Network, spec.DependencyNet, spec.DNSResolvers)...)
	args = append(args,
		"--user", ExecutorUser,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--workdir", ExecutorWorkdir,
		"--pids-limit", DefaultPidsLimit,
		"--memory", DefaultMemory,
		"--memory-swap", DefaultMemory,
		"--cpus", DefaultCPUs,
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=128m",
		"--tmpfs", "/run:rw,nosuid,nodev,size=8m",
		"--volume", spec.RepositoryPath+":/workspace:rw",
	)
	if spec.ToolsPath != "" {
		args = append(args, "--volume", spec.ToolsPath+":/opt/user-tools:rw")
	}
	if spec.CachePath != "" {
		args = append(args, "--volume", spec.CachePath+":/var/cache/harness:rw")
	}
	args = append(args,
		"--env", "HOME=/tmp/cloud-harness-home",
		"--env", "HARNESS_WORKSPACE_ROOT=/workspace",
		"--env", "GIT_CONFIG_NOSYSTEM=1",
		"--entrypoint", "/opt/harness/harness-worker",
		spec.Image,
	)
	return args
}

// ValidateSkillHelperArgs rejects raw bridge, docker.sock, tokens, and root.
func ValidateSkillHelperArgs(args []string) error {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--network bridge") {
		return fmt.Errorf("raw bridge profile is not selectable")
	}
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--volume" && ForbiddenVolume(args[i+1]) {
			return fmt.Errorf("docker socket must not be mounted into a skill helper")
		}
	}
	if !strings.Contains(joined, "--user "+ExecutorUser) {
		return fmt.Errorf("skill helper must be unprivileged")
	}
	for _, flag := range []string{"--cap-drop", "--security-opt", "--rm"} {
		if !contains(args, flag) {
			return fmt.Errorf("missing required hardening flag %s", flag)
		}
	}
	if strings.Contains(joined, "GH_TOKEN=") || strings.Contains(joined, "GITHUB_TOKEN=") {
		return fmt.Errorf("skill helper argv must not contain tokens")
	}
	if strings.Contains(strings.ToLower(joined), "docker.sock") {
		return fmt.Errorf("docker socket must not be mounted into a skill helper")
	}
	if !strings.Contains(joined, "cloud-harness.role=skill-helper") {
		return fmt.Errorf("skill helper role label is required")
	}
	return nil
}

// WorkerExecArgs is docker exec argv for the one-shot worker inside an executor.
// The JSON payload rides stdin; argv never includes tokens or docker.sock.
func WorkerExecArgs(containerName, operationID string) []string {
	return []string{
		"exec", "-i", containerName,
		"/usr/bin/setsid", "--wait",
		"/opt/harness/worker-runner.sh", operationID,
	}
}

// ValidateWorkerExecArgs rejects privileged exec, sockets, and tokens in argv.
func ValidateWorkerExecArgs(args []string) error {
	if len(args) < 7 || args[0] != "exec" || args[1] != "-i" {
		return fmt.Errorf("worker dispatch must use docker exec -i")
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--privileged") {
		return fmt.Errorf("worker exec must not be privileged")
	}
	if strings.Contains(strings.ToLower(joined), "docker.sock") {
		return fmt.Errorf("docker socket must not appear in worker exec argv")
	}
	if strings.Contains(joined, "GH_TOKEN=") || strings.Contains(joined, "GITHUB_TOKEN=") {
		return fmt.Errorf("worker exec argv must not contain tokens")
	}
	if !strings.Contains(joined, "/opt/harness/worker-runner.sh") {
		return fmt.Errorf("worker exec must invoke worker-runner.sh")
	}
	if !strings.Contains(joined, "/usr/bin/setsid") {
		return fmt.Errorf("worker exec must isolate the process group")
	}
	return nil
}

// OverlayExecutorImageOwnsGoWorker reports whether the opt-in Go executor
// Dockerfile installs the static harness-worker as the worker-runner entry.
func OverlayExecutorImageOwnsGoWorker(dockerfile string) error {
	raw, err := os.ReadFile(dockerfile)
	if err != nil {
		return err
	}
	text := string(raw)
	if !strings.Contains(text, "go build -o /out/harness-worker ./cmd/harness-worker") {
		return fmt.Errorf("Go executor image must build cmd/harness-worker")
	}
	if !strings.Contains(text, "COPY --chown=root:root worker/worker-runner.go.sh /opt/harness/worker-runner.sh") {
		return fmt.Errorf("Go executor image must install worker-runner.go.sh as worker-runner.sh")
	}
	if strings.Contains(text, "harness-worker.mjs") {
		return fmt.Errorf("Go executor image must not ship the TypeScript worker as image entry")
	}
	if !strings.Contains(text, "USER 10001:10001") {
		return fmt.Errorf("Go executor image must drop to UID 10001")
	}
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "docker.sock") {
			return fmt.Errorf("Go executor image must not mention docker.sock")
		}
		if strings.HasPrefix(strings.ToUpper(trim), "EXPOSE") {
			return fmt.Errorf("Go executor image must not publish a port")
		}
	}
	return nil
}

// ProductionRunnerImageOwnsDockerCLI reports whether the shipped Go runner
// image can talk to the host daemon. Distroless/nonroot would make
// workspace_open fail closed because Engine.cli execs the docker binary.
func ProductionRunnerImageOwnsDockerCLI(dockerfile string) error {
	raw, err := os.ReadFile(dockerfile)
	if err != nil {
		return err
	}
	text := string(raw)
	if !strings.Contains(text, "go build -o /out/runner ./cmd/runner") {
		return fmt.Errorf("Go runner image must build cmd/runner")
	}
	if !strings.Contains(text, "docker-cli") {
		return fmt.Errorf("Go runner image must install docker-cli")
	}
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		upper := strings.ToUpper(trim)
		if strings.HasPrefix(upper, "FROM ") && strings.Contains(trim, "distroless") {
			return fmt.Errorf("Go runner image must not be distroless because it execs docker")
		}
		if strings.HasPrefix(upper, "USER ") && strings.Contains(trim, "nonroot") {
			return fmt.Errorf("Go runner image must not force distroless nonroot; the host docker.sock is a root-owned unix socket")
		}
	}
	return nil
}

func workspaceExecCwd(rel string) string {
	rel = strings.ReplaceAll(strings.TrimSpace(rel), "\\", "/")
	if rel == "" || rel == "." {
		return ExecutorWorkdir
	}
	return ExecutorWorkdir + "/" + strings.TrimPrefix(rel, "/")
}

// InteractiveExecArgs is persistent docker exec argv for sessions and shells.
func InteractiveExecArgs(containerName, relCwd, recordID string) []string {
	return []string{
		"exec", "-i", "-w", workspaceExecCwd(relCwd),
		containerName, "/usr/bin/setsid", "--wait",
		"/opt/harness/shell-runner.sh", recordID,
	}
}

// TaskExecArgs is persistent docker exec argv for background tasks.
func TaskExecArgs(containerName, relCwd, taskID string, timeoutSeconds int) []string {
	if timeoutSeconds < 1 {
		timeoutSeconds = 1
	}
	return []string{
		"exec", "-i", "-w", workspaceExecCwd(relCwd),
		"-e", "CH_COMMAND",
		containerName, "/opt/harness/task-runner.sh", taskID, fmt.Sprintf("%d", timeoutSeconds),
	}
}

func validatePersistentExec(args []string, runner string) error {
	if len(args) < 6 || args[0] != "exec" || args[1] != "-i" {
		return fmt.Errorf("interactive dispatch must use docker exec -i")
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--privileged") {
		return fmt.Errorf("interactive exec must not be privileged")
	}
	if strings.Contains(strings.ToLower(joined), "docker.sock") {
		return fmt.Errorf("docker socket must not appear in interactive exec argv")
	}
	if strings.Contains(joined, "GH_TOKEN=") || strings.Contains(joined, "GITHUB_TOKEN=") {
		return fmt.Errorf("interactive exec argv must not contain tokens")
	}
	if !strings.Contains(joined, runner) {
		return fmt.Errorf("interactive exec must invoke %s", runner)
	}
	return nil
}

// ValidateInteractiveExecArgs rejects privileged exec, sockets, and tokens.
func ValidateInteractiveExecArgs(args []string) error {
	return validatePersistentExec(args, "/opt/harness/shell-runner.sh")
}

// ValidateTaskExecArgs rejects privileged exec, sockets, and tokens.
func ValidateTaskExecArgs(args []string) error {
	return validatePersistentExec(args, "/opt/harness/task-runner.sh")
}

func contains(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
