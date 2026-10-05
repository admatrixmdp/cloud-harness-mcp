package executor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func validMemoryName(name string) bool {
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

func (w Workspace) memoryRel(name string) string {
	return filepath.ToSlash(filepath.Join(".cloud-harness", "memories", name+".md"))
}

func (w Workspace) memoriesList(in pathInput) protocol.ToolResult {
	root, err := SafePath(w.root(), ".cloud-harness/memories", true)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return protocol.Success("No memories", map[string]any{"memories": []any{}})
		}
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".md")
		if !validMemoryName(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
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
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid memories_list cursor", false)
		}
		offset = n
	}
	if offset > len(names) {
		offset = len(names)
	}
	end := offset + limit
	if end > len(names) {
		end = len(names)
	}
	page := names[offset:end]
	data := map[string]any{"memories": page}
	got := protocol.Success(fmt.Sprintf("Found %d memories", len(names)), data)
	if end < len(names) {
		got.Cursor = strconv.Itoa(end)
		got.Truncated = true
		data["cursor"] = got.Cursor
		got.Data = data
	}
	return got
}

func (w Workspace) memoriesRead(in pathInput) protocol.ToolResult {
	if !validMemoryName(in.Name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "name or memoryId is required", false)
	}
	target, err := SafePath(w.root(), w.memoryRel(in.Name), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorNotFound, "memory not found", false)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		return protocol.Fail(protocol.ErrorNotFound, "memory not found", false)
	}
	return protocol.Success("Memory read", map[string]any{"name": in.Name, "content": string(body)})
}

func (w Workspace) memoriesWrite(in pathInput) protocol.ToolResult {
	if !validMemoryName(in.Name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid memory name", false)
	}
	if len(in.Content) > 262_144 {
		return protocol.Fail(protocol.ErrorInvalidInput, "memory content exceeds 262144 bytes", false)
	}
	dir, err := SafePath(w.root(), ".cloud-harness/memories", true)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	target, err := SafePath(w.root(), w.memoryRel(in.Name), true)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".tmp-mem-%s-%s.tmp", in.Name, hex.EncodeToString(nonce)))
	if err := os.WriteFile(tmp, []byte(in.Content), 0o600); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	return protocol.Success("Memory written", map[string]any{"name": in.Name, "bytes": len(in.Content)})
}

func (w Workspace) memoriesSearch(in pathInput) protocol.ToolResult {
	root, err := SafePath(w.root(), ".cloud-harness/memories", true)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	query := strings.ToLower(strings.TrimSpace(in.Query))
	if query == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "query is required", false)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return protocol.Success("No memories", map[string]any{"memories": []any{}})
		}
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	matched := make([]map[string]any, 0)
	for _, file := range files {
		name := strings.TrimSuffix(file, ".md")
		if !validMemoryName(name) {
			continue
		}
		path, err := SafePath(w.root(), w.memoryRel(name), false)
		if err != nil {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(body)
		if !strings.Contains(strings.ToLower(name), query) && !strings.Contains(strings.ToLower(content), query) {
			continue
		}
		sum := sha256.Sum256([]byte(name))
		matched = append(matched, map[string]any{
			"id":         "mem_file_" + hex.EncodeToString(sum[:6]),
			"name":       name,
			"content":    content,
			"scope":      "workspace",
			"tags":       []any{},
			"generation": 1,
		})
	}
	limit := 20
	if in.Limit != nil && *in.Limit > 0 {
		limit = *in.Limit
	}
	if limit < 1 || limit > 50 {
		return protocol.Fail(protocol.ErrorInvalidInput, "limit must be between 1 and 50", false)
	}
	offset := 0
	if in.Cursor != "" {
		n, err := strconv.Atoi(in.Cursor)
		if err != nil || n < 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid memories_search cursor", false)
		}
		offset = n
	}
	if offset > len(matched) {
		offset = len(matched)
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	page := matched[offset:end]
	data := map[string]any{"memories": page}
	got := protocol.Success(fmt.Sprintf("Found %d matching memories", len(matched)), data)
	if end < len(matched) {
		got.Cursor = strconv.Itoa(end)
		got.Truncated = true
		data["cursor"] = got.Cursor
		got.Data = data
	}
	return got
}

func (w Workspace) memoriesDelete(in pathInput) protocol.ToolResult {
	if !validMemoryName(in.Name) {
		return protocol.Fail(protocol.ErrorNotFound, "memory not found", false)
	}
	target, err := SafePath(w.root(), w.memoryRel(in.Name), false)
	if err != nil {
		return protocol.Fail(protocol.ErrorNotFound, "memory not found", false)
	}
	if err := os.Remove(target); err != nil {
		return protocol.Fail(protocol.ErrorNotFound, "memory not found", false)
	}
	return protocol.Success("Memory deleted", map[string]any{"deleted": true})
}
