package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var hookEvents = map[string]struct{}{
	"on_workspace_open": {},
	"post_checkout":     {},
	"pre_commit":        {},
	"post_commit":       {},
	"manual":            {},
}

type hookRecord struct {
	Name           string
	Events         []string
	FailurePolicy  string
	Order          int
	Argv           []string
	Cwd            string
	TimeoutMs      int
	MaxOutputBytes int
}

func (w Workspace) hooksList(in pathInput) protocol.ToolResult {
	if in.Event != "" {
		if _, ok := hookEvents[in.Event]; !ok {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid hook event", false)
		}
	}
	limit := 50
	if in.Limit != nil && *in.Limit > 0 {
		limit = *in.Limit
	}
	if limit < 1 || limit > 100 {
		return protocol.Fail(protocol.ErrorInvalidInput, "limit must be between 1 and 100", false)
	}
	offset := 0
	if in.Cursor != "" {
		n, err := strconv.Atoi(in.Cursor)
		if err != nil || n < 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid hooks_list cursor", false)
		}
		offset = n
	}
	digest, hooks, err := w.hookEntries()
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	filtered := hooks
	if in.Event != "" {
		filtered = nil
		for _, h := range hooks {
			for _, ev := range h.Events {
				if ev == in.Event {
					filtered = append(filtered, h)
					break
				}
			}
		}
	}
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	page := filtered[offset:end]
	sha := digest
	if sha == "" {
		sha = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	out := make([]map[string]any, 0, len(page))
	for _, h := range page {
		out = append(out, map[string]any{
			"name":          h.Name,
			"events":        h.Events,
			"failurePolicy": h.FailurePolicy,
			"order":         h.Order,
			"provenance": map[string]any{
				"source":        "repository",
				"trust":         "untrusted-executor",
				"mutableBy":     "repository-commit",
				"path":          ".cloud-harness/hooks.json",
				"contentSha256": sha,
				"discoveredAt":  now,
			},
		})
	}
	var manifest any
	if digest != "" {
		manifest = digest
	}
	data := map[string]any{"manifestSha256": manifest, "hooks": out}
	got := protocol.Success(fmt.Sprintf("Found %d hooks", len(filtered)), data)
	if end < len(filtered) {
		got.Cursor = strconv.Itoa(end)
		got.Truncated = true
		data["cursor"] = got.Cursor
		got.Data = data
	}
	return got
}

func (w Workspace) hooksRun(ctx context.Context, in pathInput) protocol.ToolResult {
	if !validHookName(in.Name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid hook name", false)
	}
	expected := in.ExpectedManifestSHA256
	if expected == "" {
		expected = in.ExpectedSHA256
	}
	if expected == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "expectedManifestSha256 or expectedSha256 is required to run a hook", false)
	}
	if len(expected) != 64 {
		return protocol.Fail(protocol.ErrorInvalidInput, "expectedManifestSha256 must be a 64-character hex digest", false)
	}
	digest, hooks, err := w.hookEntries()
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if digest != expected {
		return protocol.Fail(protocol.ErrorConflict, fmt.Sprintf("hook manifest SHA-256 mismatch: expected %s, got %s", expected, digest), false)
	}
	var hook hookRecord
	found := false
	for _, h := range hooks {
		if h.Name == in.Name {
			hook = h
			found = true
			break
		}
	}
	if !found {
		return protocol.Fail(protocol.ErrorNotFound, "hook not found", false)
	}
	if len(hook.Argv) == 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "hook has empty argv", false)
	}
	cwd, err := SafePath(w.root(), emptyDot(hook.Cwd), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	timeout := time.Duration(hook.TimeoutMs) * time.Millisecond
	if in.TimeoutMs > 0 {
		timeout = time.Duration(in.TimeoutMs) * time.Millisecond
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	maxBytes := hook.MaxOutputBytes
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, hook.Argv[0], hook.Argv[1:]...)
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
		} else if runCtx.Err() == context.DeadlineExceeded {
			return protocol.Fail(protocol.ErrorTimeout, "hook timed out", true)
		} else {
			return protocol.Fail(protocol.ErrorExecutionFailed, err.Error(), false)
		}
	}
	data := map[string]any{"output": buf.String(), "exitCode": exit, "signal": nil}
	if exit != 0 {
		got := protocol.Fail(protocol.ErrorExecutionFailed, fmt.Sprintf("Hook exited with %d", exit), false)
		got.Data = data
		got.Truncated = limited.truncated
		return got
	}
	got := protocol.Success(fmt.Sprintf("Hook exited with %d", exit), data)
	got.Truncated = limited.truncated
	return got
}

func validHookName(name string) bool {
	if name == "" || len(name) > 120 || strings.HasPrefix(name, "-") {
		return false
	}
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func (w Workspace) hookEntries() (string, []hookRecord, error) {
	path, err := SafePath(w.root(), ".cloud-harness/hooks.json", true)
	if err != nil {
		return "", nil, fmt.Errorf("hooks manifest path escapes workspace")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, nil
		}
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return digest, nil, nil
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return digest, nil, nil
	}
	if hooksRaw, ok := obj["hooks"].([]any); ok {
		out := make([]hookRecord, 0, len(hooksRaw))
		for _, item := range hooksRaw {
			h, ok := item.(map[string]any)
			if !ok {
				continue
			}
			rec := parseHookObject(h, digest)
			if rec.Name == "" {
				continue
			}
			out = append(out, rec)
		}
		return digest, out, nil
	}
	out := make([]hookRecord, 0, len(obj))
	for name, cmd := range obj {
		if name == "version" || name == "hooks" {
			continue
		}
		if !validHookName(name) {
			continue
		}
		command, ok := cmd.(string)
		if !ok || command == "" {
			continue
		}
		out = append(out, hookRecord{
			Name: name, Events: []string{"manual"}, FailurePolicy: "warn", Order: 100,
			Argv: []string{"/bin/bash", "-lc", command}, Cwd: ".", TimeoutMs: 60_000, MaxOutputBytes: 65536,
		})
	}
	return digest, out, nil
}

func parseHookObject(h map[string]any, _ string) hookRecord {
	name, _ := h["name"].(string)
	if !validHookName(name) {
		return hookRecord{}
	}
	events := []string{}
	if raw, ok := h["events"].([]any); ok {
		for _, item := range raw {
			s, _ := item.(string)
			if _, ok := hookEvents[s]; ok {
				events = append(events, s)
			}
		}
	}
	if ev, ok := h["event"].(string); ok && len(events) == 0 {
		if _, ok := hookEvents[ev]; ok {
			events = []string{ev}
		}
	}
	if len(events) == 0 {
		events = []string{"manual"}
	}
	policy := "warn"
	if h["failurePolicy"] == "block" {
		policy = "block"
	}
	order := 100
	switch n := h["order"].(type) {
	case float64:
		order = int(n)
	case int:
		order = n
	}
	timeoutMs := 60_000
	switch n := h["timeoutMs"].(type) {
	case float64:
		timeoutMs = int(n)
	case int:
		timeoutMs = n
	}
	maxBytes := 65536
	switch n := h["maxOutputBytes"].(type) {
	case float64:
		maxBytes = int(n)
	case int:
		maxBytes = n
	}
	cwd := "."
	if s, ok := h["cwd"].(string); ok && s != "" {
		cwd = s
	}
	return hookRecord{
		Name: name, Events: events, FailurePolicy: policy, Order: order,
		Argv: hookArgv(h), Cwd: cwd, TimeoutMs: timeoutMs, MaxOutputBytes: maxBytes,
	}
}

func hookArgv(h map[string]any) []string {
	if raw, ok := h["argv"].([]any); ok {
		out := make([]string, 0, len(raw))
		for _, item := range raw {
			s, ok := item.(string)
			if !ok || s == "" {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	if cmd, ok := h["command"].(string); ok && cmd != "" {
		return []string{"/bin/bash", "-lc", cmd}
	}
	return nil
}
