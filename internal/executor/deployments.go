package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	maxDeploymentsFileBytes = 262_144
	maxDeployments          = 100
	maxDeploymentCommand    = 32_768
)

type deploymentEntry struct {
	Name    string
	Command string
	Cwd     string
}

func validDeploymentName(name string) bool {
	if name == "" || len(name) > 120 || strings.HasPrefix(name, "-") {
		return false
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validDeploymentCwd(cwd string) bool {
	if cwd == "" || len(cwd) > 1024 {
		return false
	}
	normalized := strings.ReplaceAll(cwd, "\\", "/")
	if strings.HasPrefix(normalized, "/") || strings.Contains(normalized, "\x00") {
		return false
	}
	if len(normalized) >= 2 && unicode.IsLetter(rune(normalized[0])) && normalized[1] == ':' {
		return false
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

func (w Workspace) deploymentsList() protocol.ToolResult {
	entries, err := w.deploymentEntries()
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{"name": e.Name, "cwd": e.Cwd})
	}
	return protocol.Success(fmt.Sprintf("Found %d deployment targets", len(out)), map[string]any{"deployments": out})
}

func (w Workspace) deploymentsRun(ctx context.Context, in pathInput) protocol.ToolResult {
	if !validDeploymentName(in.Name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid deployment name", false)
	}
	entries, err := w.deploymentEntries()
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	var entry *deploymentEntry
	for i := range entries {
		if entries[i].Name == in.Name {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		return protocol.Fail(protocol.ErrorNotFound, "deployment target not found", false)
	}
	cwd, err := SafePath(w.root(), emptyDot(entry.Cwd), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	timeout := 60 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "/bin/bash", "-lc", entry.Command)
	cmd.Dir = cwd
	cmd.Env = confinedEnv()
	var buf bytes.Buffer
	limited := &limitedWriter{max: MaxInternalOutput, buf: &buf}
	cmd.Stdout = limited
	cmd.Stderr = limited
	err = cmd.Run()
	exit := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exit = exitErr.ExitCode()
		} else if runCtx.Err() == context.DeadlineExceeded {
			return protocol.Fail(protocol.ErrorTimeout, "deployment timed out", true)
		} else {
			return protocol.Fail(protocol.ErrorExecutionFailed, err.Error(), false)
		}
	}
	data := map[string]any{"output": buf.String(), "exitCode": exit, "signal": nil}
	if exit != 0 {
		msg := fmt.Sprintf("Deployment target exited with %d", exit)
		got := protocol.Fail(protocol.ErrorConflict, msg, false)
		got.Data = data
		got.Truncated = limited.truncated
		return got
	}
	got := protocol.Success("Deployment target completed", data)
	got.Truncated = limited.truncated
	return got
}

func (w Workspace) deploymentEntries() ([]deploymentEntry, error) {
	path, err := SafePath(w.root(), ".cloud-harness/deployments.json", true)
	if err != nil {
		return nil, fmt.Errorf("deployments configuration path escapes workspace")
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []deploymentEntry{}, nil
		}
		return nil, err
	}
	if info.Size() > maxDeploymentsFileBytes {
		return nil, fmt.Errorf("deployments configuration is too large")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("deployments configuration must contain valid JSON")
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("deployments configuration must be an object")
	}
	if len(obj) > maxDeployments {
		return nil, fmt.Errorf("too many deployment targets")
	}
	out := make([]deploymentEntry, 0, len(obj))
	for name, value := range obj {
		if !validDeploymentName(name) {
			return nil, fmt.Errorf("invalid deployment name")
		}
		command := ""
		cwd := "."
		switch v := value.(type) {
		case string:
			command = v
		case map[string]any:
			c, _ := v["command"].(string)
			command = c
			if extra, ok := v["cwd"].(string); ok {
				cwd = extra
			} else if v["cwd"] != nil {
				return nil, fmt.Errorf("invalid deployment cwd for %s", name)
			}
		default:
			return nil, fmt.Errorf("invalid deployment %s", name)
		}
		if command == "" || len(command) > maxDeploymentCommand {
			return nil, fmt.Errorf("invalid deployment %s", name)
		}
		if !validDeploymentCwd(cwd) {
			return nil, fmt.Errorf("invalid deployment cwd for %s", name)
		}
		out = append(out, deploymentEntry{Name: name, Command: command, Cwd: cwd})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
