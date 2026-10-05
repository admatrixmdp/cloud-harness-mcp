package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	Path                   string   `json:"path"`
	Content                string   `json:"content"`
	ExpectedSHA256         string   `json:"expectedSha256"`
	Cursor                 string   `json:"cursor"`
	Offset                 *int     `json:"offset"`
	Limit                  *int     `json:"limit"`
	ReadAll                bool     `json:"readAll"`
	Cwd                    string   `json:"cwd"`
	Command                string   `json:"command"`
	TimeoutMs              int      `json:"timeoutMs"`
	MaxOutputBytes         int      `json:"maxOutputBytes"`
	OldText                string   `json:"oldText"`
	NewText                string   `json:"newText"`
	Pattern                string   `json:"pattern"`
	Glob                   string   `json:"glob"`
	MaxResults             int      `json:"maxResults"`
	Source                 string   `json:"source"`
	Destination            string   `json:"destination"`
	Overwrite              bool     `json:"overwrite"`
	ContentBase64          string   `json:"contentBase64"`
	Query                  string   `json:"query"`
	Symbol                 string   `json:"symbol"`
	Action                 string   `json:"action"`
	Name                   string   `json:"name"`
	StartPoint             string   `json:"startPoint"`
	Force                  bool     `json:"force"`
	Ref                    string   `json:"ref"`
	Create                 bool     `json:"create"`
	CreateBranch           bool     `json:"createBranch"`
	IncludeShadowed        *bool    `json:"includeShadowed"`
	All                    bool     `json:"all"`
	Paths                  []string `json:"paths"`
	Message                string   `json:"message"`
	AuthorName             string   `json:"authorName"`
	AuthorEmail            string   `json:"authorEmail"`
	FastForward            string   `json:"fastForward"`
	Upstream               string   `json:"upstream"`
	Mode                   string   `json:"mode"`
	Event                  string   `json:"event"`
	ExpectedManifestSHA256 string   `json:"expectedManifestSha256"`
	ExpectedContentSHA256  string   `json:"expectedContentSha256"`
	Script                 string   `json:"script"`
	Prompt                 string   `json:"prompt"`
	IdempotencyKey         string   `json:"idempotencyKey"`
	SessionID              string   `json:"sessionId"`
	ShellID                string   `json:"shellId"`
	Input                  string   `json:"input"`
	WaitMs                 int      `json:"waitMs"`
	TaskID                 string   `json:"taskId"`
	OperationID            string   `json:"operationId"`
	DependsOn              []string `json:"dependsOn"`
	Args                   []string `json:"args"`
	Files                  []struct {
		Path           string `json:"path"`
		Content        string `json:"content"`
		ExpectedSHA256 string `json:"expectedSha256"`
	} `json:"files"`
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
	case protocol.OpFilesWriteBatch:
		return w.writeBatch(in)
	case protocol.OpFilesMove:
		return w.move(in)
	case protocol.OpGrepSearch:
		return w.grep(ctx, in)
	case protocol.OpSymbolsSearch:
		return w.symbolsSearch(in)
	case protocol.OpSymbolsReferences:
		return w.symbolsReferences(ctx, in)
	case protocol.OpExecRun:
		return w.exec(ctx, in)
	case protocol.OpGitStatus:
		return w.gitStatus(ctx)
	case protocol.OpGitDiff:
		return w.gitCmd(ctx, "Git diff", "diff", "--no-ext-diff")
	case protocol.OpGitLog:
		return w.gitCmd(ctx, "Git log", "log", "--oneline", "-n", "50")
	case protocol.OpGitBranch:
		return w.gitBranch(ctx, in)
	case protocol.OpGitCheckout:
		return w.gitCheckout(ctx, in)
	case protocol.OpGitAdd:
		return w.gitAdd(ctx, in)
	case protocol.OpGitCommit:
		return w.gitCommit(ctx, in)
	case protocol.OpGitMerge:
		return w.gitMerge(ctx, in)
	case protocol.OpGitRebase:
		return w.gitRebase(ctx, in)
	case protocol.OpWorktreesList:
		return w.worktreesList(ctx)
	case protocol.OpWorktreesCreate:
		return w.worktreesCreate(ctx, in)
	case protocol.OpWorktreesRemove:
		return w.worktreesRemove(ctx, in)
	case protocol.OpSkillsList:
		return w.skillsList(in)
	case protocol.OpSkillsRead:
		return w.skillsRead(in)
	case protocol.OpSkillsRun:
		return w.skillsRun(ctx, in)
	case protocol.OpSkillSuggest:
		return w.skillSuggest(in)
	case protocol.OpSessionsList:
		return w.sessionsList(in)
	case protocol.OpSessionsOpen:
		return w.sessionsOpen(in)
	case protocol.OpSessionsIO:
		return w.sessionsIO(in)
	case protocol.OpSessionsClose:
		return w.sessionsClose(in)
	case protocol.OpShellOpen:
		return w.shellOpen(in)
	case protocol.OpShellIO:
		return w.shellIO(in)
	case protocol.OpShellClose:
		return w.shellClose(in)
	case protocol.OpTasksList:
		return w.tasksList(in)
	case protocol.OpTasksRun:
		return w.tasksRun(in)
	case protocol.OpTasksStatus:
		return w.tasksStatus(in)
	case protocol.OpTasksCancel:
		return w.tasksCancel(in)
	case protocol.OpTasksGraph:
		return w.tasksGraph()
	case protocol.OpOperationStatus:
		return w.operationStatus(in)
	case protocol.OpOperationCancel:
		return w.operationCancel(in)
	case protocol.OpOperationWait:
		return w.operationWait(in)
	case protocol.OpHooksList:
		return w.hooksList(in)
	case protocol.OpHooksRun:
		return w.hooksRun(ctx, in)
	case protocol.OpDeploymentsList:
		return w.deploymentsList()
	case protocol.OpDeploymentsRun:
		return w.deploymentsRun(ctx, in)
	case protocol.OpMemoriesList:
		return w.memoriesList(in)
	case protocol.OpMemoriesRead:
		return w.memoriesRead(in)
	case protocol.OpMemoriesWrite:
		return w.memoriesWrite(in)
	case protocol.OpMemoriesSearch:
		return w.memoriesSearch(in)
	case protocol.OpMemoriesDelete:
		return w.memoriesDelete(in)
	case protocol.OpWorkspaceRecover:
		return w.recover(ctx, in)
	case protocol.OpArtifactsRestore:
		return w.artifactsRestore(in)
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

func (w Workspace) artifactsRestore(in pathInput) protocol.ToolResult {
	if in.Path == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid destination path", false)
	}
	if in.ContentBase64 == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "contentBase64 is required", false)
	}
	target, err := SafePath(w.root(), in.Path, true)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "path "+in.Path+" escapes workspace", false)
	}
	info, err := os.Lstat(target)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return protocol.Fail(protocol.ErrorInternal, "failed to inspect "+in.Path, false)
	}
	if exists && info.IsDir() {
		return protocol.Fail(protocol.ErrorInvalidInput, "destination path is a directory", false)
	}
	if exists && !in.Overwrite {
		return protocol.Fail(protocol.ErrorConflict, "destination file already exists", false)
	}
	content, err := base64.StdEncoding.DecodeString(in.ContentBase64)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "contentBase64 is required", false)
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if in.ExpectedSHA256 != "" && digest != in.ExpectedSHA256 {
		return protocol.Fail(protocol.ErrorConflict, "artifact hash mismatch", false)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	tmp := filepath.Join(filepath.Dir(target), fmt.Sprintf(".cloud-harness-%d-%s.tmp", os.Getpid(), randomHex(8)))
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	return protocol.Success("Artifact restored to workspace", map[string]any{
		"path":      in.Path,
		"sizeBytes": len(content),
		"sha256":    digest,
	})
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

func (w Workspace) writeBatch(in pathInput) protocol.ToolResult {
	if len(in.Files) == 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "files array is required and cannot be empty", false)
	}
	normalized := make([]string, len(in.Files))
	for i, item := range in.Files {
		normalized[i] = strings.ReplaceAll(item.Path, "\\", "/")
	}
	for i, left := range normalized {
		for j, right := range normalized {
			if i != j && strings.HasPrefix(right, left+"/") {
				return protocol.Fail(protocol.ErrorConflict, "ancestor conflict: "+left+" is both a file and parent of "+right, false)
			}
		}
	}
	type prepared struct {
		path    string
		target  string
		content string
		exists  bool
	}
	items := make([]prepared, 0, len(in.Files))
	for _, item := range in.Files {
		if item.Path == "" {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid file path", false)
		}
		target, err := SafePath(w.root(), item.Path, true)
		if err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "path "+item.Path+" escapes workspace", false)
		}
		current, err := os.ReadFile(target)
		exists := err == nil
		if err != nil && !os.IsNotExist(err) {
			return protocol.Fail(protocol.ErrorInternal, "failed to inspect "+item.Path, false)
		}
		if item.ExpectedSHA256 != "" {
			if !exists {
				return protocol.Fail(protocol.ErrorConflict, "target "+item.Path+" does not exist for expectedSha256", false)
			}
			sum := sha256.Sum256(current)
			if hex.EncodeToString(sum[:]) != item.ExpectedSHA256 {
				return protocol.Fail(protocol.ErrorConflict, "file "+item.Path+" changed since it was read", false)
			}
		}
		items = append(items, prepared{path: item.Path, target: target, content: item.Content, exists: exists})
	}
	written := make([]map[string]any, 0, len(items))
	created, updated := 0, 0
	temps := make([]string, 0, len(items))
	defer func() {
		for _, tmp := range temps {
			_ = os.Remove(tmp)
		}
	}()
	for i, item := range items {
		if err := os.MkdirAll(filepath.Dir(item.target), 0o755); err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
		}
		tmp := fmt.Sprintf("%s.cloud-harness-batch-%d-%s-%d.tmp", item.target, os.Getpid(), randomHex(8), i)
		if err := os.WriteFile(tmp, []byte(item.content), 0o600); err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
		}
		temps = append(temps, tmp)
		if err := os.Rename(tmp, item.target); err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
		}
		temps[len(temps)-1] = ""
		sum := sha256.Sum256([]byte(item.content))
		status := "created"
		if item.exists {
			status = "updated"
			updated++
		} else {
			created++
		}
		written = append(written, map[string]any{
			"path": item.path, "sha256": hex.EncodeToString(sum[:]), "bytes": len(item.content), "status": status,
		})
	}
	return protocol.Success(fmt.Sprintf("Batch wrote %d files (%d created, %d updated)", len(written), created, updated), map[string]any{
		"createdCount": created, "updatedCount": updated, "totalFiles": len(written), "files": written,
	})
}

func (w Workspace) move(in pathInput) protocol.ToolResult {
	if in.Source == "" || in.Destination == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "source and destination are required", false)
	}
	source, err := SafePath(w.root(), in.Source, false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	destination, err := SafePath(w.root(), in.Destination, true)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if source == destination {
		return protocol.Success("Path already at destination", map[string]any{"source": in.Source, "destination": in.Destination})
	}
	if info, err := os.Lstat(destination); err == nil {
		if !in.Overwrite {
			return protocol.Fail(protocol.ErrorConflict, "destination already exists", false)
		}
		if info.IsDir() {
			return protocol.Fail(protocol.ErrorConflict, "overwrite does not replace directories", false)
		}
		if err := os.Remove(destination); err != nil {
			return protocol.Fail(protocol.ErrorConflict, err.Error(), false)
		}
	} else if !os.IsNotExist(err) {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	if err := os.Rename(source, destination); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	return protocol.Success("Path moved", map[string]any{"source": in.Source, "destination": in.Destination})
}

func (w Workspace) symbolsSearch(in pathInput) protocol.ToolResult {
	if in.Query == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "query is required", false)
	}
	target, err := SafePath(w.root(), emptyDot(in.Path), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	maxResults := in.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}
	query := strings.ToLower(in.Query)
	var symbols []map[string]any
	_ = filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || len(symbols) >= maxResults {
			return nil
		}
		rel, err := filepath.Rel(w.root(), path)
		if err != nil {
			return nil
		}
		name := d.Name()
		if !strings.Contains(strings.ToLower(name), query) {
			return nil
		}
		symbols = append(symbols, map[string]any{"name": name, "path": filepath.ToSlash(rel), "kind": "file"})
		return nil
	})
	result := protocol.Success(fmt.Sprintf("Found %d symbol definitions", len(symbols)), map[string]any{"symbols": symbols})
	result.Truncated = len(symbols) >= maxResults
	return result
}

func (w Workspace) symbolsReferences(ctx context.Context, in pathInput) protocol.ToolResult {
	if in.Symbol == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "symbol is required", false)
	}
	got := w.grep(ctx, pathInput{Path: in.Path, Pattern: in.Symbol, Glob: in.Glob, MaxResults: in.MaxResults})
	if !got.OK {
		return got
	}
	data, _ := got.Data.(map[string]any)
	result := protocol.Success("Found lexical references", map[string]any{"references": data["matches"]})
	result.Truncated = got.Truncated
	return result
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
	return w.gitCmd(ctx, "Git status", "status", "--short", "--branch", "--untracked-files=all")
}

func validGitArg(value string) bool {
	return value != "" && !strings.HasPrefix(value, "-") && !strings.Contains(value, "\x00") && len(value) <= 255
}

func (w Workspace) gitBranch(ctx context.Context, in pathInput) protocol.ToolResult {
	action := in.Action
	if action == "" {
		action = "list"
	}
	var args []string
	switch action {
	case "list":
		args = []string{"branch", "--list", "--format=%(refname:short)"}
	case "create":
		if !validGitArg(in.Name) {
			return protocol.Fail(protocol.ErrorInvalidInput, "name is required for create and delete", false)
		}
		args = []string{"branch", in.Name}
		if in.StartPoint != "" {
			if !validGitArg(in.StartPoint) {
				return protocol.Fail(protocol.ErrorInvalidInput, "startPoint cannot start with a dash", false)
			}
			args = append(args, in.StartPoint)
		}
	case "delete":
		if !validGitArg(in.Name) {
			return protocol.Fail(protocol.ErrorInvalidInput, "name is required for create and delete", false)
		}
		flag := "-d"
		if in.Force {
			flag = "-D"
		}
		args = []string{"branch", flag, in.Name}
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "action must be list, create, or delete", false)
	}
	got := w.gitCmd(ctx, "Git branch operation complete", args...)
	if !got.OK || exitOf(got) == 0 {
		return got
	}
	return protocol.Fail(protocol.ErrorConflict, stringFrom(got, "output"), false)
}

func (w Workspace) gitCheckout(ctx context.Context, in pathInput) protocol.ToolResult {
	if !validGitArg(in.Ref) {
		return protocol.Fail(protocol.ErrorInvalidInput, "ref is required and cannot start with a dash", false)
	}
	args := []string{"checkout"}
	if in.Create {
		args = append(args, "-b")
	}
	args = append(args, in.Ref)
	got := w.gitCmd(ctx, "Git checkout complete", args...)
	if !got.OK || exitOf(got) == 0 {
		return got
	}
	return protocol.Fail(protocol.ErrorConflict, stringFrom(got, "output"), false)
}

func (w Workspace) gitAdd(ctx context.Context, in pathInput) protocol.ToolResult {
	if in.All && len(in.Paths) > 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "paths must be empty when all is true", false)
	}
	if !in.All && len(in.Paths) == 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "paths are required unless all is true", false)
	}
	args := []string{"add"}
	if in.All {
		args = append(args, "--all")
	} else {
		for _, p := range in.Paths {
			if _, err := SafePath(w.root(), p, false); err != nil {
				return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
			}
		}
		args = append(args, "--")
		args = append(args, in.Paths...)
	}
	got := w.gitCmd(ctx, "Git changes staged", args...)
	if !got.OK || exitOf(got) == 0 {
		return got
	}
	return protocol.Fail(protocol.ErrorConflict, stringFrom(got, "output"), false)
}

func (w Workspace) gitCommit(ctx context.Context, in pathInput) protocol.ToolResult {
	if strings.TrimSpace(in.Message) == "" || len(in.Message) > 10_000 {
		return protocol.Fail(protocol.ErrorInvalidInput, "message is required", false)
	}
	if in.All {
		added := w.gitCmd(ctx, "Git changes staged", "add", "--all")
		if !added.OK || exitOf(added) != 0 {
			if !added.OK {
				return added
			}
			return protocol.Fail(protocol.ErrorConflict, stringFrom(added, "output"), false)
		}
	}
	name := in.AuthorName
	if name == "" {
		name = "Cloud Harness Agent"
	}
	email := in.AuthorEmail
	if email == "" {
		email = "agent@cloud-harness.local"
	}
	if strings.ContainsAny(name, "\n\x00") || strings.ContainsAny(email, "\n\x00") {
		return protocol.Fail(protocol.ErrorInvalidInput, "author fields must not contain newlines", false)
	}
	got := w.gitCmd(ctx, "Git commit created", "-c", "user.name="+name, "-c", "user.email="+email, "commit", "--no-gpg-sign", "-m", in.Message)
	if !got.OK || exitOf(got) != 0 {
		if !got.OK {
			return got
		}
		return protocol.Fail(protocol.ErrorConflict, stringFrom(got, "output"), false)
	}
	if data, ok := got.Data.(map[string]any); ok {
		data["authorName"] = name
		data["authorEmail"] = email
	}
	return got
}

func (w Workspace) gitMerge(ctx context.Context, in pathInput) protocol.ToolResult {
	if !validGitArg(in.Ref) {
		return protocol.Fail(protocol.ErrorInvalidInput, "ref is required and cannot start with a dash", false)
	}
	args := []string{"merge", "--no-edit"}
	switch in.FastForward {
	case "", "allow":
	case "only":
		args = append(args, "--ff-only")
	case "never":
		args = append(args, "--no-ff")
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "fastForward must be allow, only, or never", false)
	}
	if in.Message != "" {
		if strings.ContainsAny(in.Message, "\x00") {
			return protocol.Fail(protocol.ErrorInvalidInput, "message must not contain null bytes", false)
		}
		args = append(args, "-m", in.Message)
	}
	args = append(args, in.Ref)
	got := w.gitCmd(ctx, "Git merge complete", args...)
	if !got.OK || exitOf(got) == 0 {
		return got
	}
	return protocol.Fail(protocol.ErrorConflict, stringFrom(got, "output"), false)
}

func validWorktreeName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 80 {
		return false
	}
	if strings.HasPrefix(name, "-") || strings.Contains(name, "\x00") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
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

func (w Workspace) worktreesList(ctx context.Context) protocol.ToolResult {
	return w.gitCmd(ctx, "Git worktrees", "worktree", "list", "--porcelain")
}

func (w Workspace) worktreesCreate(ctx context.Context, in pathInput) protocol.ToolResult {
	if !validWorktreeName(in.Name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "name is required and cannot start with a dash", false)
	}
	if !validGitArg(in.Ref) {
		return protocol.Fail(protocol.ErrorInvalidInput, "ref is required and cannot start with a dash", false)
	}
	location := ".worktrees/" + in.Name
	if _, err := SafePath(w.root(), location, true); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if _, err := SafePath(w.root(), ".worktrees", true); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if err := os.MkdirAll(filepath.Join(w.root(), ".worktrees"), 0o755); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	args := []string{"worktree", "add"}
	if in.CreateBranch {
		args = append(args, "-b", in.Name)
	}
	args = append(args, location, in.Ref)
	got := w.gitCmd(ctx, "Worktree created", args...)
	if !got.OK || exitOf(got) != 0 {
		if !got.OK {
			return got
		}
		return protocol.Fail(protocol.ErrorConflict, optionalGitOut(got), false)
	}
	if data, ok := got.Data.(map[string]any); ok {
		data["name"] = in.Name
		data["path"] = location
	}
	return got
}

func (w Workspace) worktreesRemove(ctx context.Context, in pathInput) protocol.ToolResult {
	if !validWorktreeName(in.Name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "name is required and cannot start with a dash", false)
	}
	location := ".worktrees/" + in.Name
	if _, err := SafePath(w.root(), location, true); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	args := []string{"worktree", "remove"}
	if in.Force {
		args = append(args, "--force")
	}
	args = append(args, location)
	got := w.gitCmd(ctx, "Worktree removed", args...)
	if !got.OK || exitOf(got) != 0 {
		if !got.OK {
			return got
		}
		return protocol.Fail(protocol.ErrorConflict, optionalGitOut(got), false)
	}
	if data, ok := got.Data.(map[string]any); ok {
		data["name"] = in.Name
	}
	return got
}

func (w Workspace) gitRebase(ctx context.Context, in pathInput) protocol.ToolResult {
	action := in.Action
	if action == "" {
		action = "start"
	}
	args := []string{"rebase"}
	switch action {
	case "continue":
		args = append(args, "--continue")
	case "abort":
		args = append(args, "--abort")
	case "start":
		if !validGitArg(in.Upstream) {
			return protocol.Fail(protocol.ErrorInvalidInput, "upstream is required when starting a rebase", false)
		}
		args = append(args, in.Upstream)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "action must be start, continue, or abort", false)
	}
	got := w.gitCmd(ctx, "Git rebase "+action+" complete", args...)
	if !got.OK || exitOf(got) == 0 {
		return got
	}
	return protocol.Fail(protocol.ErrorConflict, stringFrom(got, "output"), false)
}

func (w Workspace) recover(ctx context.Context, in pathInput) protocol.ToolResult {
	mode := in.Mode
	if mode == "" {
		mode = "status"
	}
	switch mode {
	case "status":
		return w.recoverStatus(ctx)
	case "patch":
		return w.recoverPatch(ctx)
	case "snapshot_commit":
		return w.recoverSnapshot(ctx, in)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unsupported recovery mode "+mode, false)
	}
}

func (w Workspace) recoverStatus(ctx context.Context) protocol.ToolResult {
	status := w.gitCmd(ctx, "status", "status", "--short", "--branch", "--untracked-files=all")
	logRes := w.gitCmd(ctx, "log", "log", "-10", "--date=iso-strict", "--pretty=format:%H%x09%aI%x09%an%x09%s")
	unpushed := w.gitCmd(ctx, "unpushed", "log", "@{u}..HEAD", "--oneline")
	statusOut := optionalGitOut(status)
	logOut := optionalGitOut(logRes)
	unpushedOut := optionalGitOut(unpushed)
	if exitOf(unpushed) != 0 {
		unpushedOut = logOut
	}
	hasUncommitted := false
	for _, line := range strings.Split(statusOut, "\n") {
		if line != "" && !strings.HasPrefix(line, "##") {
			hasUncommitted = true
			break
		}
	}
	return protocol.Success("Workspace recovery status", map[string]any{
		"status":         statusOut,
		"recentLog":      logOut,
		"unpushed":       unpushedOut,
		"hasUncommitted": hasUncommitted,
	})
}

func (w Workspace) recoverPatch(ctx context.Context) protocol.ToolResult {
	tmp, err := os.CreateTemp("", "cloud-harness-temp-index-")
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, "could not create temporary git index", false)
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpName)
	indexPath := filepath.Join(w.root(), ".git", "index")
	if raw, err := os.ReadFile(indexPath); err == nil {
		_ = os.WriteFile(tmpName, raw, 0o600)
	}
	env := []string{"GIT_INDEX_FILE=" + tmpName}
	_ = w.gitCmdEnv(ctx, env, "intent add", "add", "-N", "--all")
	head := w.gitCmdEnv(ctx, env, "head diff", "diff", "HEAD", "--no-ext-diff", "--no-textconv")
	staged := w.gitCmd(ctx, "staged", "diff", "--cached", "--no-ext-diff", "--no-textconv")
	unpushed := w.gitCmd(ctx, "unpushed", "diff", "@{u}..HEAD", "--no-ext-diff", "--no-textconv")
	headOut := optionalGitOut(head)
	stagedOut := optionalGitOut(staged)
	unpushedOut := optionalGitOut(unpushed)
	working := headOut
	if working == "" {
		working = stagedOut
	}
	combined := strings.TrimSpace(strings.Join(filterEmpty(unpushedOut, headOut), "\n"))
	return protocol.Success("Workspace recovery patch", map[string]any{
		"workingTreePatch": working,
		"stagedPatch":      stagedOut,
		"unpushedPatch":    unpushedOut,
		"combinedPatch":    combined,
	})
}

func (w Workspace) recoverSnapshot(ctx context.Context, in pathInput) protocol.ToolResult {
	status := w.gitCmd(ctx, "status", "status", "--short", "--untracked-files=all")
	if !status.OK {
		return status
	}
	if exitOf(status) != 0 {
		return protocol.Fail(protocol.ErrorInternal, optionalGitOut(status), true)
	}
	hasChanges := false
	for _, line := range strings.Split(optionalGitOut(status), "\n") {
		if line != "" && !strings.HasPrefix(line, "##") {
			hasChanges = true
			break
		}
	}
	if hasChanges {
		added := w.gitCmd(ctx, "add", "add", "--all")
		if !added.OK || exitOf(added) != 0 {
			return protocol.Fail(protocol.ErrorInternal, stringFrom(added, "output"), true)
		}
		name := in.AuthorName
		if name == "" {
			name = "Cloud Harness Recovery"
		}
		email := in.AuthorEmail
		if email == "" {
			email = "recovery@cloud-harness.local"
		}
		if strings.ContainsAny(name, "\n\x00") || strings.ContainsAny(email, "\n\x00") {
			return protocol.Fail(protocol.ErrorInvalidInput, "author fields must not contain newlines", false)
		}
		message := in.Message
		if message == "" {
			message = "chore(recovery): snapshot uncommitted work for export"
		}
		committed := w.gitCmd(ctx, "commit", "-c", "user.name="+name, "-c", "user.email="+email, "commit", "--no-gpg-sign", "-m", message)
		if !committed.OK || exitOf(committed) != 0 {
			return protocol.Fail(protocol.ErrorInternal, stringFrom(committed, "output"), true)
		}
	}
	head := w.gitCmd(ctx, "head", "rev-parse", "HEAD")
	if !head.OK || exitOf(head) != 0 {
		return protocol.Fail(protocol.ErrorInternal, stringFrom(head, "output"), true)
	}
	return protocol.Success("Recovery snapshot committed", map[string]any{
		"headCommitSha":    strings.TrimSpace(stringFrom(head, "output")),
		"committedChanges": hasChanges,
	})
}

func optionalGitOut(got protocol.ToolResult) string {
	if !got.OK {
		return ""
	}
	data, _ := got.Data.(map[string]any)
	s, _ := data["output"].(string)
	return s
}

func filterEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func exitOf(got protocol.ToolResult) int {
	data, _ := got.Data.(map[string]any)
	switch v := data["exitCode"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

func stringFrom(got protocol.ToolResult, key string) string {
	data, _ := got.Data.(map[string]any)
	s, _ := data[key].(string)
	if s == "" {
		return "Git operation failed"
	}
	return s
}

func (w Workspace) gitCmd(ctx context.Context, message string, args ...string) protocol.ToolResult {
	return w.gitCmdEnv(ctx, nil, message, args...)
}

func (w Workspace) gitCmdEnv(ctx context.Context, extraEnv []string, message string, args ...string) protocol.ToolResult {
	full := append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.pager=cat"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = w.root()
	cmd.Env = append(confinedEnv(), extraEnv...)
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
	result := protocol.Success(message, map[string]any{"output": string(clipped), "exitCode": exit})
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
