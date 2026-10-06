package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const maxTasksPerRoot = 128

type taskRecord struct {
	id          string
	root        string
	command     string
	cwd         string
	timeoutMs   int
	dependsOn   []string
	fingerprint string
	status      string
	exitCode    any
	createdAt   int64
	relCwd      string
	container   string
	spawn       func(args []string, extraEnv []string) (*exec.Cmd, error)
	cmd         *exec.Cmd
	mu          sync.Mutex
	buf         bytes.Buffer
	offset      int
	truncated   bool
}

type taskHub struct {
	mu    sync.Mutex
	byID  map[string]*taskRecord
	byKey map[string]string
}

var tasks = taskHub{
	byID:  map[string]*taskRecord{},
	byKey: map[string]string{},
}

func taskFingerprint(command, cwd string, timeoutMs int, dependsOn []string) string {
	sorted := append([]string{}, dependsOn...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	raw, _ := json.Marshal(map[string]any{"command": command, "cwd": emptyDot(cwd), "timeoutMs": timeoutMs, "dependsOn": sorted})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (h *taskHub) run(root, command, cwd, key string, timeoutMs int, dependsOn []string, container string, spawn func(args []string, extraEnv []string) (*exec.Cmd, error)) protocol.ToolResult {
	if strings.TrimSpace(command) == "" || len(command) > 32_768 {
		return protocol.Fail(protocol.ErrorInvalidInput, "command is required", false)
	}
	if !protocol.ValidIdempotencyKey(key) {
		return protocol.Fail(protocol.ErrorInvalidInput, "idempotencyKey is required", false)
	}
	absCwd, err := SafePath(root, emptyDot(cwd), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if timeoutMs <= 0 {
		timeoutMs = 900_000
	}
	seen := map[string]struct{}{}
	for _, dep := range dependsOn {
		if !protocol.ValidOpaqueID(protocol.PrefixTask, dep) {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid task dependency", false)
		}
		if _, ok := seen[dep]; ok {
			return protocol.Fail(protocol.ErrorInvalidInput, "task dependencies must be unique", false)
		}
		seen[dep] = struct{}{}
	}
	relCwd, err := normalizeRel(emptyDot(cwd))
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	fp := taskFingerprint(command, relCwd, timeoutMs, dependsOn)
	mapKey := root + ":" + key
	h.mu.Lock()
	if priorID, ok := h.byKey[mapKey]; ok {
		rec := h.byID[priorID]
		h.mu.Unlock()
		if rec.fingerprint != fp {
			return protocol.Fail(protocol.ErrorConflict, "Idempotency key reused with different task parameters", false)
		}
		got := protocol.Success("Idempotent task result", rec.view())
		return got
	}
	n := 0
	for _, rec := range h.byID {
		if rec.root == root {
			n++
		}
	}
	if n >= maxTasksPerRoot {
		h.mu.Unlock()
		return protocol.Fail(protocol.ErrorLimitExceeded, "too many tasks", false)
	}
	for _, dep := range dependsOn {
		other := h.byID[dep]
		if other == nil || other.root != root {
			h.mu.Unlock()
			return protocol.Fail(protocol.ErrorNotFound, "task dependency "+dep+" not found", false)
		}
	}
	rec := &taskRecord{
		id:          protocol.NewOpaqueID(protocol.PrefixTask),
		root:        root,
		command:     command,
		cwd:         absCwd,
		relCwd:      relCwd,
		container:   container,
		spawn:       spawn,
		timeoutMs:   timeoutMs,
		dependsOn:   append([]string{}, dependsOn...),
		fingerprint: fp,
		status:      "queued",
		exitCode:    nil,
		createdAt:   time.Now().UnixMilli(),
	}
	h.byID[rec.id] = rec
	h.byKey[mapKey] = rec.id
	h.mu.Unlock()
	h.reconcile(root)
	return protocol.Success("Task started", rec.view())
}

func (h *taskHub) reconcile(root string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, rec := range h.byID {
		if rec.root != root || rec.status != "queued" {
			continue
		}
		blocked := false
		ready := true
		for _, dep := range rec.dependsOn {
			other := h.byID[dep]
			if other == nil || other.root != root {
				blocked = true
				break
			}
			other.mu.Lock()
			st := other.status
			other.mu.Unlock()
			if st == "failed" || st == "cancelled" || st == "blocked" {
				blocked = true
				break
			}
			if st != "succeeded" {
				ready = false
			}
		}
		if blocked {
			rec.mu.Lock()
			rec.status = "blocked"
			rec.mu.Unlock()
			continue
		}
		if ready {
			h.startLocked(rec)
		}
	}
}

func (h *taskHub) startLocked(rec *taskRecord) {
	rec.mu.Lock()
	if rec.status != "queued" {
		rec.mu.Unlock()
		return
	}
	rec.status = "running"
	timeout := time.Duration(rec.timeoutMs) * time.Millisecond
	cmd, err := startTaskCmd(rec)
	if err != nil {
		rec.status = "failed"
		rec.exitCode = 1
		rec.mu.Unlock()
		return
	}
	cmd.Stdout = rec
	cmd.Stderr = rec
	rec.cmd = cmd
	rec.mu.Unlock()
	if err := cmd.Start(); err != nil {
		rec.mu.Lock()
		rec.status = "failed"
		rec.exitCode = 1
		rec.mu.Unlock()
		return
	}
	go func() {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		var err error
		select {
		case err = <-done:
		case <-time.After(timeout):
			_ = cmd.Process.Kill()
			err = <-done
			rec.mu.Lock()
			if rec.status == "running" {
				rec.status = "failed"
				rec.exitCode = 124
			}
			rec.mu.Unlock()
			h.reconcile(rec.root)
			return
		}
		rec.mu.Lock()
		if rec.status == "running" {
			if err == nil {
				rec.status = "succeeded"
				rec.exitCode = 0
			} else if exitErr, ok := err.(*exec.ExitError); ok {
				rec.status = "failed"
				rec.exitCode = exitErr.ExitCode()
			} else {
				rec.status = "failed"
				rec.exitCode = 1
			}
		}
		rec.mu.Unlock()
		h.reconcile(rec.root)
	}()
}

func (h *taskHub) get(root, id string) *taskRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[id]
	if rec == nil || rec.root != root {
		return nil
	}
	return rec
}

func (h *taskHub) status(root, id, cursor string) protocol.ToolResult {
	if !protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		return protocol.Fail(protocol.ErrorInvalidInput, "taskId is required", false)
	}
	rec := h.get(root, id)
	if rec == nil {
		return protocol.Fail(protocol.ErrorNotFound, "task not found", false)
	}
	page, err := rec.viewSince(cursor)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	got := protocol.Success("Task status", page.data)
	got.Cursor = page.cursor
	got.Truncated = page.truncated
	return got
}

func (h *taskHub) cancel(root, id string) protocol.ToolResult {
	if !protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		return protocol.Fail(protocol.ErrorInvalidInput, "taskId is required", false)
	}
	rec := h.get(root, id)
	if rec == nil {
		return protocol.Fail(protocol.ErrorNotFound, "task not found", false)
	}
	rec.mu.Lock()
	if rec.status == "queued" || rec.status == "running" {
		rec.status = "cancelled"
		if rec.cmd != nil && rec.cmd.Process != nil {
			_ = rec.cmd.Process.Kill()
		}
	}
	view := rec.unlockedView()
	rec.mu.Unlock()
	h.reconcile(root)
	return protocol.Success("Task cancelled", view)
}

func (h *taskHub) list(root, cursor string, limit int) protocol.ToolResult {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		return protocol.Fail(protocol.ErrorInvalidInput, "limit must be between 1 and 100", false)
	}
	offset := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil || n < 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid task cursor", false)
		}
		offset = n
	}
	h.mu.Lock()
	all := make([]*taskRecord, 0)
	for _, rec := range h.byID {
		if rec.root == root {
			all = append(all, rec)
		}
	}
	h.mu.Unlock()
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].createdAt < all[i].createdAt {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	if offset > len(all) {
		offset = len(all)
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	page := make([]map[string]any, 0, end-offset)
	for _, rec := range all[offset:end] {
		page = append(page, rec.summary())
	}
	data := map[string]any{"tasks": page}
	got := protocol.Success("Tasks listed", data)
	if end < len(all) {
		got.Cursor = strconv.Itoa(end)
		got.Truncated = true
		data["cursor"] = got.Cursor
		got.Data = data
	}
	return got
}

func (h *taskHub) graph(root string) protocol.ToolResult {
	h.mu.Lock()
	all := make([]*taskRecord, 0)
	for _, rec := range h.byID {
		if rec.root == root {
			all = append(all, rec)
		}
	}
	h.mu.Unlock()
	nodes := make([]map[string]any, 0, len(all))
	edges := make([]map[string]any, 0)
	for _, rec := range all {
		nodes = append(nodes, rec.summary())
		for _, dep := range rec.dependsOn {
			edges = append(edges, map[string]any{"from": dep, "to": rec.id})
		}
	}
	return protocol.Success("Task dependency graph", map[string]any{"nodes": nodes, "edges": edges})
}

func (r *taskRecord) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	remain := sessionMaxBytes - r.buf.Len()
	if remain <= 0 {
		r.truncated = true
		dropped := len(p)
		if dropped > r.buf.Len() {
			dropped = r.buf.Len()
		}
		if dropped > 0 {
			next := r.buf.Bytes()[dropped:]
			r.offset += dropped
			r.buf.Reset()
			r.buf.Write(next)
			remain = sessionMaxBytes - r.buf.Len()
		}
	}
	if len(p) > remain {
		r.truncated = true
		_, err := r.buf.Write(p[:remain])
		return len(p), err
	}
	return r.buf.Write(p)
}

func (r *taskRecord) view() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.unlockedView()
}

func (r *taskRecord) unlockedView() map[string]any {
	return map[string]any{
		"id":        r.id,
		"status":    r.status,
		"exitCode":  r.exitCode,
		"output":    r.buf.String(),
		"dependsOn": r.dependsOn,
	}
}

func (r *taskRecord) summary() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"id":        r.id,
		"status":    r.status,
		"exitCode":  r.exitCode,
		"dependsOn": r.dependsOn,
	}
}

func (r *taskRecord) viewSince(cursor string) (sessionPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	requested := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil || n < 0 {
			return sessionPage{}, fmt.Errorf("invalid output cursor")
		}
		requested = n
	}
	end := r.offset + r.buf.Len()
	if requested > end {
		return sessionPage{}, fmt.Errorf("invalid output cursor")
	}
	missed := requested < r.offset
	start := requested - r.offset
	if start < 0 {
		start = 0
	}
	raw := r.buf.Bytes()[start:]
	if len(raw) > sessionPageBytes {
		raw = raw[:sessionPageBytes]
	}
	next := r.offset + start + len(raw)
	data := r.unlockedView()
	data["output"] = string(raw)
	return sessionPage{data: data, cursor: strconv.Itoa(next), truncated: missed || next < end || r.truncated}, nil
}

func startTaskCmd(rec *taskRecord) (*exec.Cmd, error) {
	if rec.spawn != nil && rec.container != "" {
		seconds := rec.timeoutMs / 1000
		if seconds < 1 {
			seconds = 1
		}
		args := sandbox.TaskExecArgs(rec.container, rec.relCwd, rec.id, seconds)
		if err := sandbox.ValidateTaskExecArgs(args); err != nil {
			return nil, err
		}
		return rec.spawn(args, []string{"CH_COMMAND=" + rec.command})
	}
	cmd := exec.Command("/bin/bash", "-lc", rec.command)
	cmd.Dir = rec.cwd
	cmd.Env = confinedEnv()
	return cmd, nil
}

func (w Workspace) tasksRun(in pathInput) protocol.ToolResult {
	return tasks.run(w.root(), in.Command, in.Cwd, in.IdempotencyKey, in.TimeoutMs, in.DependsOn, w.Container, w.Spawn)
}

func (w Workspace) tasksStatus(in pathInput) protocol.ToolResult {
	return tasks.status(w.root(), in.TaskID, in.Cursor)
}

func (w Workspace) tasksCancel(in pathInput) protocol.ToolResult {
	return tasks.cancel(w.root(), in.TaskID)
}

func (w Workspace) tasksList(in pathInput) protocol.ToolResult {
	limit := 50
	if in.Limit != nil && *in.Limit > 0 {
		limit = *in.Limit
	}
	return tasks.list(w.root(), in.Cursor, limit)
}

func (w Workspace) tasksGraph() protocol.ToolResult {
	return tasks.graph(w.root())
}
