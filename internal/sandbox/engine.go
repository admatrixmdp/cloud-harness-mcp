package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// Result is a bounded docker CLI invocation.
type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

// Runner invokes docker. Tests inject a fake.
type Runner func(ctx context.Context, args []string, stdin string) (Result, error)

// Starter starts a long-lived docker exec. Tests inject a fake.
type Starter func(args []string, extraEnv []string) (*exec.Cmd, error)

// Engine talks to the host Docker CLI. Only the runner process should use this.
type Engine struct {
	Image      string
	InstanceID string
	Run        Runner
	Start      Starter
	Timeout    time.Duration
	MaxBytes   int
}

func (e Engine) timeout() time.Duration {
	if e.Timeout > 0 {
		return e.Timeout
	}
	return 30 * time.Second
}

func (e Engine) maxBytes() int {
	if e.MaxBytes > 0 {
		return e.MaxBytes
	}
	return 1 << 20
}

func (e Engine) runner() Runner {
	if e.Run != nil {
		return e.Run
	}
	return e.cli
}

func (e Engine) cli(ctx context.Context, args []string, stdin string) (Result, error) {
	if err := ValidateCreateArgs(args); err != nil && args[0] == "create" {
		return Result{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout())
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitWriter{buf: &stdout, max: e.maxBytes()}
	cmd.Stderr = &limitWriter{buf: &stderr, max: e.maxBytes()}
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: 0}
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exit.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("%s: docker unavailable: %w", protocol.ErrorUnavailable, err)
	}
	return res, nil
}

type limitWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	remain := w.max - w.buf.Len()
	if remain <= 0 {
		return len(p), nil
	}
	if len(p) > remain {
		p = p[:remain]
	}
	return w.buf.Write(p)
}

// CreateExecutor builds docker create argv from Cloud Harness policy, then
// starts the container. TypeScript createExecutor does the same: docker exec
// cannot talk to a created-but-stopped executor.
func (e Engine) CreateExecutor(ctx context.Context, spec ExecutorSpec) (string, error) {
	if spec.Image == "" {
		spec.Image = e.Image
	}
	if spec.InstanceID == "" {
		spec.InstanceID = e.InstanceID
	}
	args := CreateArgs(spec)
	if err := ValidateCreateArgs(args); err != nil {
		return "", err
	}
	res, err := e.runner()(ctx, args, "")
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s: executor creation failed", protocol.ErrorUnavailable)
	}
	started, err := e.runner()(ctx, []string{"start", spec.Name}, "")
	if err != nil {
		_, _ = e.runner()(ctx, []string{"rm", "--force", spec.Name}, "")
		return "", err
	}
	if started.ExitCode != 0 {
		_, _ = e.runner()(ctx, []string{"rm", "--force", spec.Name}, "")
		return "", fmt.Errorf("%s: executor start failed", protocol.ErrorUnavailable)
	}
	return spec.Name, nil
}

// RemoveExecutor force-removes a managed container by name.
func (e Engine) RemoveExecutor(ctx context.Context, name string) error {
	_, err := e.runner()(ctx, []string{"rm", "--force", name}, "")
	return err
}

// Invoke runs docker with the given argv. Tests inject Engine.Run; production uses the CLI.
func (e Engine) Invoke(ctx context.Context, args []string, stdin string) (Result, error) {
	return e.runner()(ctx, args, stdin)
}

// Spawn starts a long-lived docker exec. Extra env is applied to the docker CLI
// child only so values such as CH_COMMAND never appear in argv.
func (e Engine) Spawn(args []string, extraEnv []string) (*exec.Cmd, error) {
	if e.Start != nil {
		return e.Start(args, extraEnv)
	}
	cmd := exec.Command("docker", args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	return cmd, nil
}

// HelperStdin is the documented token transport: one line on docker run stdin.
func HelperStdin(token string) string {
	if token == "" {
		return "\n"
	}
	return token + "\n"
}
