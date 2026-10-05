package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// Request is the one-shot stdin JSON the runner pipes into the worker.
type Request struct {
	Operation protocol.Operation `json:"operation"`
	Input     json.RawMessage    `json:"input"`
}

// Workspace is a confined executor root.
type Workspace struct {
	Root string
}

func (w Workspace) root() string {
	if w.Root != "" {
		return w.Root
	}
	return Root()
}

type pathInput struct {
	Path           string `json:"path"`
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expectedSha256"`
	Cursor         string `json:"cursor"`
	Offset         *int   `json:"offset"`
	Limit          *int   `json:"limit"`
	ReadAll        bool   `json:"readAll"`
	Cwd            string `json:"cwd"`
	Command        string `json:"command"`
	TimeoutMs      int    `json:"timeoutMs"`
	MaxOutputBytes int    `json:"maxOutputBytes"`
	OldText        string `json:"oldText"`
	NewText        string `json:"newText"`
	Pattern        string `json:"pattern"`
	Glob           string `json:"glob"`
	MaxResults     int    `json:"maxResults"`
}

// Execute handles one worker operation. Unknown operations stay INVALID_INPUT.
func (w Workspace) Execute(ctx context.Context, op protocol.Operation, input json.RawMessage) protocol.ToolResult {
	var in pathInput
	if len(input) > 0 {
		if err := json.Unmarshal(input, &in); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid worker input", false)
		}
	}
	switch op {
	case protocol.OpFilesList:
		return w.list(in)
	case protocol.OpFilesRead:
		return w.read(in)
	case protocol.OpFilesWrite:
		return w.write(in)
	case protocol.OpFilesDelete:
		return w.delete(in)
	case protocol.OpFilesMkdir:
		return w.mkdir(in)
	case protocol.OpFilesApplyPatch:
		return w.patch(in)
	case protocol.OpGrepSearch:
		return w.grep(ctx, in)
	case protocol.OpExecRun:
		return w.exec(ctx, in)
	case protocol.OpGitStatus:
		return w.gitStatus(ctx)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unsupported worker operation "+string(op), false)
	}
}

func (w Workspace) list(in pathInput) protocol.ToolResult {
	target, err := SafePath(w.root(), emptyDot(in.Path), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	offset := 0
	if in.Cursor != "" {
		offset, _ = strconv.Atoi(in.Cursor)
	}
	limit := 100
	if in.Limit != nil && *in.Limit > 0 {
		limit = *in.Limit
	}
	end := offset + limit
	if end > len(entries) {
		end = len(entries)
	}
	if offset > len(entries) {
		offset = len(entries)
	}
	page := make([]map[string]any, 0, end-offset)
	for _, entry := range entries[offset:end] {
		kind := "file"
		switch {
		case entry.IsDir():
			kind = "directory"
		case entry.Type()&os.ModeSymlink != 0:
			kind = "symlink"
		}
		page = append(page, map[string]any{"name": entry.Name(), "type": kind})
	}
	result := protocol.Success(fmt.Sprintf("Listed %d entries", len(page)), map[string]any{
		"path":    emptyDot(in.Path),
		"entries": page,
	})
	if end < len(entries) {
		result.Cursor = strconv.Itoa(end)
	}
	return result
}

func (w Workspace) read(in pathInput) protocol.ToolResult {
	target, err := SafePath(w.root(), in.Path, false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	value, err := os.ReadFile(target)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	total := len(value)
	sum := sha256.Sum256(value)
	fileSHA := hex.EncodeToString(sum[:])
	tag := fileSHA[:16]
	offset := 0
	if in.Offset != nil {
		offset = *in.Offset
	}
	if in.Cursor != "" {
		parts := strings.Split(in.Cursor, ":")
		offset, _ = strconv.Atoi(parts[0])
		if offset < 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid cursor offset", false)
		}
		if len(parts) > 1 && parts[1] != "" && parts[1] != tag {
			return protocol.Fail(protocol.ErrorConflict, "stale cursor: file changed since initial read", false)
		}
	}
	limit := DefaultReadLimit
	if in.ReadAll {
		limit = MaxInternalOutput
	} else if in.Limit != nil && *in.Limit > 0 {
		limit = *in.Limit
	}
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	truncated := end < total
	result := protocol.Success(fmt.Sprintf("Read %d bytes", end-offset), map[string]any{
		"path":          in.Path,
		"content":       string(value[offset:end]),
		"sha256":        fileSHA,
		"bytesReturned": end - offset,
		"totalBytes":    total,
		"eof":           !truncated,
	})
	result.Truncated = truncated
	if truncated {
		result.Cursor = fmt.Sprintf("%d:%s", end, tag)
	}
	return result
}

func (w Workspace) write(in pathInput) protocol.ToolResult {
	target, err := SafePath(w.root(), in.Path, true)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if in.ExpectedSHA256 != "" {
		current, err := os.ReadFile(target)
		if err != nil {
			return protocol.Fail(protocol.ErrorConflict, "target does not exist for expectedSha256", false)
		}
		sum := sha256.Sum256(current)
		if hex.EncodeToString(sum[:]) != in.ExpectedSHA256 {
			return protocol.Fail(protocol.ErrorConflict, "file changed since it was read", false)
		}
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	tmp := fmt.Sprintf("%s.cloud-harness-%d-%s.tmp", target, os.Getpid(), randomHex(8))
	if err := os.WriteFile(tmp, []byte(in.Content), 0o600); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	sum := sha256.Sum256([]byte(in.Content))
	return protocol.Success("File written", map[string]any{
		"path":   in.Path,
		"bytes":  len(in.Content),
		"sha256": hex.EncodeToString(sum[:]),
	})
}

func (w Workspace) delete(in pathInput) protocol.ToolResult {
	target, err := SafePath(w.root(), in.Path, false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if err := os.RemoveAll(target); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	return protocol.Success("deleted", map[string]any{"path": in.Path})
}

func (w Workspace) mkdir(in pathInput) protocol.ToolResult {
	target, err := SafePath(w.root(), in.Path, true)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	return protocol.Success("directory created", map[string]any{"path": in.Path})
}

func (w Workspace) patch(in pathInput) protocol.ToolResult {
	if in.OldText == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "oldText is required", false)
	}
	target, err := SafePath(w.root(), in.Path, false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	current, err := os.ReadFile(target)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if in.ExpectedSHA256 != "" {
		sum := sha256.Sum256(current)
		if hex.EncodeToString(sum[:]) != in.ExpectedSHA256 {
			return protocol.Fail(protocol.ErrorConflict, "file changed since it was read", false)
		}
	}
	text := string(current)
	first := strings.Index(text, in.OldText)
	if first < 0 {
		return protocol.Fail(protocol.ErrorConflict, "oldText was not found", false)
	}
	second := strings.Index(text[first+max(1, len(in.OldText)):], in.OldText)
	if second >= 0 {
		return protocol.Fail(protocol.ErrorConflict, "oldText is not unique", false)
	}
	next := text[:first] + in.NewText + text[first+len(in.OldText):]
	tmp := fmt.Sprintf("%s.cloud-harness-patch-%d-%s.tmp", target, os.Getpid(), randomHex(8))
	if err := os.WriteFile(tmp, []byte(next), 0o600); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	sum := sha256.Sum256([]byte(next))
	return protocol.Success("Patch applied", map[string]any{"path": in.Path, "sha256": hex.EncodeToString(sum[:])})
}

func (w Workspace) grep(ctx context.Context, in pathInput) protocol.ToolResult {
	if in.Pattern == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "pattern is required", false)
	}
	target, err := SafePath(w.root(), emptyDot(in.Path), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	maxResults := in.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	matches, truncated, err := confinedGrep(ctx, w.root(), target, in.Pattern, in.Glob, maxResults, 262144)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	result := protocol.Success("Search complete", map[string]any{"matches": matches})
	result.Truncated = truncated
	return result
}

func (w Workspace) exec(ctx context.Context, in pathInput) protocol.ToolResult {
	if in.Command == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "command is required", false)
	}
	cwd, err := SafePath(w.root(), emptyDot(in.Cwd), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	timeout := 60 * time.Second
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	maxBytes := in.MaxOutputBytes
	if maxBytes <= 0 {
		maxBytes = MaxInternalOutput
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/bash", "-lc", in.Command)
	cmd.Dir = cwd
	cmd.Env = confinedEnv()
	var buf bytes.Buffer
	limited := &limitedWriter{max: maxBytes, buf: &buf}
	cmd.Stdout = limited
	cmd.Stderr = limited
	err = cmd.Run()
	exit := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exit = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			return protocol.Fail(protocol.ErrorTimeout, "command timed out", true)
		} else {
			return protocol.Fail(protocol.ErrorExecutionFailed, err.Error(), false)
		}
	}
	result := protocol.Success(fmt.Sprintf("Command exited with %d", exit), map[string]any{
		"output":   buf.String(),
		"exitCode": exit,
		"signal":   nil,
	})
	result.Truncated = limited.truncated
	return result
}

func (w Workspace) gitStatus(ctx context.Context) protocol.ToolResult {
	cmd := exec.CommandContext(ctx, "git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "status", "--short", "--branch", "--untracked-files=all")
	cmd.Dir = w.root()
	cmd.Env = confinedEnv()
	out, err := cmd.CombinedOutput()
	clipped, truncated := Truncate(out, MaxInternalOutput)
	exit := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exit = exitErr.ExitCode()
		} else {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
		}
	}
	result := protocol.Success("Git status", map[string]any{"output": string(clipped), "exitCode": exit})
	result.Truncated = truncated
	return result
}

type limitedWriter struct {
	max       int
	buf       *bytes.Buffer
	truncated bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remain := w.max - w.buf.Len()
	if remain <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > remain {
		w.truncated = true
		_, err := w.buf.Write(p[:remain])
		return len(p), err
	}
	return w.buf.Write(p)
}

func confinedEnv() []string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp/cloud-harness-home"
	}
	out := []string{
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
		"PAGER=cat",
		"PATH=" + os.Getenv("PATH"),
	}
	return out
}

func emptyDot(p string) string {
	if p == "" {
		return "."
	}
	return p
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// HandleStdin reads one JSON request from r and writes one JSON result to w.
func HandleStdin(r io.Reader, w io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return err
	}
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return json.NewEncoder(w).Encode(protocol.Fail(protocol.ErrorInvalidInput, "worker request must contain valid JSON", false))
	}
	result := (Workspace{}).Execute(context.Background(), req.Operation, req.Input)
	return json.NewEncoder(w).Encode(result)
}
