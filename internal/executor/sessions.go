package executor

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	maxSessionsPerRoot = 32
	sessionPageBytes   = 65_536
	sessionMaxBytes    = 262_144
)

type sessionRecord struct {
	id             string
	root           string
	name           string
	cwd            string
	status         string
	exitCode       any
	createdAt      int64
	idempotencyKey string
	relCwd         string
	container      string
	cmd            *exec.Cmd
	stdin          io.WriteCloser
	mu             sync.Mutex
	buf            bytes.Buffer
	offset         int
	truncated      bool
}

type sessionHub struct {
	mu      sync.Mutex
	byID    map[string]*sessionRecord
	byKey   map[string]string
	running map[string]string
}

type interactiveKind struct {
	prefix   string
	openMsg  string
	ioMsg    string
	closeMsg string
	notFound string
	needName bool
	limitMsg string
}

var (
	sessionKind = interactiveKind{
		prefix: protocol.PrefixSession, openMsg: "Coding session opened", ioMsg: "Coding session output",
		closeMsg: "Coding session closed", notFound: "interactive session not found", needName: true,
		limitMsg: "too many running sessions",
	}
	shellKind = interactiveKind{
		prefix: protocol.PrefixShell, openMsg: "Shell opened", ioMsg: "Shell output",
		closeMsg: "Shell closed", notFound: "interactive session not found", needName: false,
		limitMsg: "too many running shells",
	}
	sessions = sessionHub{byID: map[string]*sessionRecord{}, byKey: map[string]string{}, running: map[string]string{}}
	shells   = sessionHub{byID: map[string]*sessionRecord{}, byKey: map[string]string{}, running: map[string]string{}}
)

func validSessionName(name string) bool {
	if name == "" || len(name) > 80 || strings.HasPrefix(name, "-") {
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

func (h *sessionHub) open(kind interactiveKind, root, name, cwd, key, container string, spawn func(args []string, extraEnv []string) (*exec.Cmd, error)) protocol.ToolResult {
	if kind.needName && !validSessionName(name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid session name", false)
	}
	if !protocol.ValidIdempotencyKey(key) {
		return protocol.Fail(protocol.ErrorInvalidInput, "idempotencyKey is required", false)
	}
	relCwd, err := normalizeRel(emptyDot(cwd))
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	absCwd, err := SafePath(root, relCwd, false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	mapKey := root + ":" + key
	h.mu.Lock()
	if priorID, ok := h.byKey[mapKey]; ok {
		rec := h.byID[priorID]
		h.mu.Unlock()
		return protocol.Success(kind.openMsg, rec.view())
	}
	n := 0
	for _, rec := range h.byID {
		if rec.root == root && rec.status == "running" {
			n++
		}
	}
	if n >= maxSessionsPerRoot {
		h.mu.Unlock()
		return protocol.Fail(protocol.ErrorLimitExceeded, kind.limitMsg, false)
	}
	if kind.needName {
		if existingID, ok := h.running[root+":"+name]; ok {
			if rec := h.byID[existingID]; rec != nil && rec.status == "running" {
				h.mu.Unlock()
				return protocol.Fail(protocol.ErrorConflict, "session "+name+" is already running", false)
			}
		}
	}
	rec := &sessionRecord{
		id:             protocol.NewOpaqueID(kind.prefix),
		root:           root,
		name:           name,
		cwd:            absCwd,
		relCwd:         relCwd,
		container:      container,
		status:         "running",
		exitCode:       nil,
		createdAt:      time.Now().UnixMilli(),
		idempotencyKey: key,
	}
	cmd, err := startInteractiveCmd(rec.id, absCwd, container, relCwd, spawn)
	if err != nil {
		h.mu.Unlock()
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		h.mu.Unlock()
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	rec.cmd = cmd
	rec.stdin = stdin
	cmd.Stdout = rec
	cmd.Stderr = rec
	if err := cmd.Start(); err != nil {
		h.mu.Unlock()
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	go func() {
		err := cmd.Wait()
		rec.mu.Lock()
		defer rec.mu.Unlock()
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
	}()
	h.byID[rec.id] = rec
	h.byKey[mapKey] = rec.id
	if kind.needName {
		h.running[root+":"+name] = rec.id
	}
	h.mu.Unlock()
	return protocol.Success(kind.openMsg, rec.view())
}

func (h *sessionHub) io(kind interactiveKind, root, id, input, cursor string, waitMs int) protocol.ToolResult {
	if !protocol.ValidOpaqueID(kind.prefix, id) {
		return protocol.Fail(protocol.ErrorInvalidInput, kind.prefix+" id is required", false)
	}
	h.mu.Lock()
	rec := h.byID[id]
	h.mu.Unlock()
	if rec == nil || rec.root != root {
		return protocol.Fail(protocol.ErrorNotFound, kind.notFound, false)
	}
	if input != "" {
		if len(input) > 65_536 {
			return protocol.Fail(protocol.ErrorInvalidInput, "input exceeds bound", false)
		}
		rec.mu.Lock()
		running := rec.status == "running"
		stdin := rec.stdin
		rec.mu.Unlock()
		if running && stdin != nil {
			if _, err := io.WriteString(stdin, input); err != nil {
				return protocol.Fail(protocol.ErrorConflict, "session stdin is closed", false)
			}
		}
	}
	if waitMs > 0 {
		if waitMs > 5_000 {
			waitMs = 5_000
		}
		time.Sleep(time.Duration(waitMs) * time.Millisecond)
	}
	page, err := rec.viewSince(cursor)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	got := protocol.Success(kind.ioMsg, page.data)
	got.Cursor = page.cursor
	got.Truncated = page.truncated
	return got
}

func (h *sessionHub) close(kind interactiveKind, root, id string) protocol.ToolResult {
	if !protocol.ValidOpaqueID(kind.prefix, id) {
		return protocol.Fail(protocol.ErrorInvalidInput, kind.prefix+" id is required", false)
	}
	h.mu.Lock()
	rec := h.byID[id]
	h.mu.Unlock()
	if rec == nil || rec.root != root {
		return protocol.Fail(protocol.ErrorNotFound, kind.notFound, false)
	}
	rec.mu.Lock()
	if rec.status == "running" {
		rec.status = "cancelled"
		if rec.stdin != nil {
			_ = rec.stdin.Close()
		}
		if rec.cmd != nil && rec.cmd.Process != nil {
			_ = rec.cmd.Process.Kill()
		}
	}
	view := rec.unlockedView()
	rec.mu.Unlock()
	return protocol.Success(kind.closeMsg, view)
}

func (h *sessionHub) list(root string, cursor string, limit int) protocol.ToolResult {
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
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid session cursor", false)
		}
		offset = n
	}
	h.mu.Lock()
	all := make([]*sessionRecord, 0)
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
	data := map[string]any{"sessions": page}
	got := protocol.Success("Coding sessions listed", data)
	if end < len(all) {
		got.Cursor = strconv.Itoa(end)
		got.Truncated = true
		data["cursor"] = got.Cursor
		got.Data = data
	}
	return got
}

func (r *sessionRecord) Write(p []byte) (int, error) {
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

func (r *sessionRecord) view() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.unlockedView()
}

func (r *sessionRecord) unlockedView() map[string]any {
	out := map[string]any{
		"id":       r.id,
		"status":   r.status,
		"exitCode": r.exitCode,
		"output":   r.buf.String(),
	}
	if r.name != "" {
		out["name"] = r.name
	}
	return out
}

func (r *sessionRecord) summary() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"id":       r.id,
		"status":   r.status,
		"exitCode": r.exitCode,
		"name":     r.name,
	}
}

type sessionPage struct {
	data      map[string]any
	cursor    string
	truncated bool
}

func (r *sessionRecord) viewSince(cursor string) (sessionPage, error) {
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

func startInteractiveCmd(id, absCwd, container, relCwd string, spawn func(args []string, extraEnv []string) (*exec.Cmd, error)) (*exec.Cmd, error) {
	if spawn != nil && container != "" {
		args := sandbox.InteractiveExecArgs(container, relCwd, id)
		if err := sandbox.ValidateInteractiveExecArgs(args); err != nil {
			return nil, err
		}
		return spawn(args, nil)
	}
	cmd := exec.Command("/bin/bash", "--noprofile", "--norc", "-i")
	cmd.Dir = absCwd
	cmd.Env = confinedEnv()
	return cmd, nil
}

func (w Workspace) sessionsOpen(in pathInput) protocol.ToolResult {
	return sessions.open(sessionKind, w.root(), in.Name, in.Cwd, in.IdempotencyKey, w.Container, w.Spawn)
}

func (w Workspace) sessionsIO(in pathInput) protocol.ToolResult {
	wait := in.WaitMs
	if wait < 0 {
		wait = 0
	}
	return sessions.io(sessionKind, w.root(), in.SessionID, in.Input, in.Cursor, wait)
}

func (w Workspace) sessionsClose(in pathInput) protocol.ToolResult {
	return sessions.close(sessionKind, w.root(), in.SessionID)
}

func (w Workspace) shellOpen(in pathInput) protocol.ToolResult {
	return shells.open(shellKind, w.root(), "", in.Cwd, in.IdempotencyKey, w.Container, w.Spawn)
}

func (w Workspace) shellIO(in pathInput) protocol.ToolResult {
	wait := in.WaitMs
	if wait < 0 {
		wait = 0
	}
	return shells.io(shellKind, w.root(), in.ShellID, in.Input, in.Cursor, wait)
}

func (w Workspace) shellClose(in pathInput) protocol.ToolResult {
	return shells.close(shellKind, w.root(), in.ShellID)
}

func (w Workspace) sessionsList(in pathInput) protocol.ToolResult {
	limit := 50
	if in.Limit != nil && *in.Limit > 0 {
		limit = *in.Limit
	}
	return sessions.list(w.root(), in.Cursor, limit)
}
