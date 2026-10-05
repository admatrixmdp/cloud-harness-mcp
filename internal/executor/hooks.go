package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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
	Name          string
	Events        []string
	FailurePolicy string
	Order         int
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
		if _, ok := cmd.(string); !ok {
			continue
		}
		out = append(out, hookRecord{
			Name: name, Events: []string{"manual"}, FailurePolicy: "warn", Order: 100,
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
	return hookRecord{Name: name, Events: events, FailurePolicy: policy, Order: order}
}
