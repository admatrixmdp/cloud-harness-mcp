package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var skillNameOK = func(name string) bool {
	if name == "" || len(name) > 120 {
		return false
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' || r == ':' {
			continue
		}
		return false
	}
	return true
}

type skillCandidate struct {
	Name          string
	Source        string
	Root          string
	File          string
	SkillDir      string
	ContentSHA256 string
}

type skillEntry struct {
	Name           string
	SelectedSource string
	Source         string
	Root           string
	File           string
	ContentSHA256  string
	Shadowed       []map[string]any
	All            []skillCandidate
}

func skillTrust(source string) (trust, mutableBy string) {
	switch source {
	case "built-in":
		return "trusted-control-plane", "release"
	case "owner":
		return "owner-controlled", "owner"
	case "workspace":
		return "untrusted-executor", "workspace-process"
	default:
		return "untrusted-executor", "repository-commit"
	}
}

func (w Workspace) skillsList(in pathInput) protocol.ToolResult {
	entries, err := w.skillEntries()
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
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
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skills_list cursor", false)
		}
		offset = n
	}
	includeShadowed := true
	if in.IncludeShadowed != nil {
		includeShadowed = *in.IncludeShadowed
	}
	if offset > len(entries) {
		offset = len(entries)
	}
	end := offset + limit
	if end > len(entries) {
		end = len(entries)
	}
	page := entries[offset:end]
	out := make([]map[string]any, 0, len(page))
	for _, e := range page {
		item := map[string]any{
			"name":           e.Name,
			"selectedSource": e.SelectedSource,
			"source":         e.Source,
			"root":           e.Root,
			"contentSha256":  e.ContentSHA256,
		}
		if includeShadowed {
			item["shadowed"] = e.Shadowed
		} else {
			item["shadowed"] = []any{}
		}
		out = append(out, item)
	}
	data := map[string]any{"skills": out}
	got := protocol.Success(fmt.Sprintf("Found %d skills", len(entries)), data)
	if end < len(entries) {
		got.Cursor = strconv.Itoa(end)
		got.Truncated = true
		data["cursor"] = got.Cursor
		got.Data = data
	}
	return got
}

func (w Workspace) skillsRead(in pathInput) protocol.ToolResult {
	if !skillNameOK(in.Name) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill name", false)
	}
	entries, err := w.skillEntries()
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	var entry *skillEntry
	for i := range entries {
		if entries[i].Name == in.Name {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		return protocol.Fail(protocol.ErrorNotFound, "skill not found", false)
	}
	selected := entry.All[0]
	if in.Source != "" {
		found := false
		for _, cand := range entry.All {
			if cand.Source == in.Source {
				selected = cand
				found = true
				break
			}
		}
		if !found {
			return protocol.Fail(protocol.ErrorNotFound, "skill source not found", false)
		}
	}
	body, err := os.ReadFile(selected.File)
	if err != nil {
		return protocol.Fail(protocol.ErrorNotFound, "skill not found", false)
	}
	if in.ExpectedSHA256 != "" && selected.ContentSHA256 != in.ExpectedSHA256 {
		return protocol.Fail(protocol.ErrorConflict, "skill content changed since it was listed", false)
	}
	offset := 0
	if in.Offset != nil {
		offset = *in.Offset
	}
	if offset < 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill offset", false)
	}
	limit := 65_536
	if in.Limit != nil && *in.Limit > 0 {
		limit = *in.Limit
	}
	if limit < 1 || limit > 262_144 {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill limit", false)
	}
	total := len(body)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	trust, mutable := skillTrust(selected.Source)
	truncated := end < total
	got := protocol.Success("Skill read", map[string]any{
		"name":          entry.Name,
		"source":        selected.Source,
		"root":          selected.Root,
		"content":       string(body[offset:end]),
		"contentSha256": selected.ContentSHA256,
		"totalBytes":    total,
		"provenance": map[string]any{
			"source":        selected.Source,
			"trust":         trust,
			"mutableBy":     mutable,
			"path":          selected.File,
			"contentSha256": selected.ContentSHA256,
			"discoveredAt":  time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	got.Truncated = truncated
	return got
}

func (w Workspace) skillEntries() ([]skillEntry, error) {
	builtin := os.Getenv("BUILTIN_SKILLS_ROOT")
	if builtin == "" {
		builtin = "/opt/cloud-harness/skills"
	}
	owner := os.Getenv("CH_OWNER_SKILLS_ROOT")
	if owner == "" {
		owner = "/opt/cloud-harness/owner-skills"
	}
	groups := []struct {
		source string
		roots  []string
		abs    bool
	}{
		{"built-in", []string{builtin}, true},
		{"owner", []string{owner}, true},
		{"workspace", []string{".cloud-harness/skills"}, false},
		{"repository", []string{".agents/skills", ".codex/skills", ".claude/skills"}, false},
	}
	var all []skillCandidate
	for _, group := range groups {
		for _, root := range group.roots {
			absolute := root
			if !group.abs {
				resolved, err := SafePath(w.root(), root, true)
				if err != nil {
					continue
				}
				absolute = resolved
			}
			entries, err := os.ReadDir(absolute)
			if err != nil {
				continue
			}
			for _, item := range entries {
				if !item.IsDir() || !skillNameOK(item.Name()) {
					continue
				}
				skillDir := filepath.Join(absolute, item.Name())
				file := filepath.Join(skillDir, "SKILL.md")
				info, err := os.Stat(file)
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				digest, err := skillBundleDigest(skillDir)
				if err != nil {
					continue
				}
				all = append(all, skillCandidate{
					Name: item.Name(), Source: group.source, Root: root,
					File: file, SkillDir: skillDir, ContentSHA256: digest,
				})
			}
		}
	}
	precedence := map[string]int{"built-in": 4, "owner": 3, "workspace": 2, "repository": 1}
	repoSub := map[string]int{".agents/skills": 3, ".codex/skills": 2, ".claude/skills": 1}
	grouped := map[string][]skillCandidate{}
	for _, cand := range all {
		grouped[cand.Name] = append(grouped[cand.Name], cand)
	}
	out := make([]skillEntry, 0, len(grouped))
	for name, cands := range grouped {
		sort.SliceStable(cands, func(i, j int) bool {
			p := precedence[cands[i].Source] - precedence[cands[j].Source]
			if p != 0 {
				return p > 0
			}
			if cands[i].Source == "repository" && cands[j].Source == "repository" {
				return repoSub[cands[i].Root] > repoSub[cands[j].Root]
			}
			return false
		})
		selected := cands[0]
		shadowed := make([]map[string]any, 0, len(cands)-1)
		for _, c := range cands[1:] {
			shadowed = append(shadowed, map[string]any{
				"source":        c.Source,
				"root":          c.Root,
				"contentSha256": c.ContentSHA256,
				"reason":        "Shadowed by higher-precedence " + selected.Source + " skill in " + selected.Root,
			})
		}
		out = append(out, skillEntry{
			Name: name, SelectedSource: selected.Source, Source: selected.Source,
			Root: selected.Root, File: selected.File, ContentSHA256: selected.ContentSHA256,
			Shadowed: shadowed, All: cands,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func skillBundleDigest(skillDir string) (string, error) {
	canonical, err := filepath.EvalSymlinks(skillDir)
	if err != nil {
		canonical = skillDir
	}
	canonical = filepath.Clean(canonical)
	var parts []string
	err = filepath.WalkDir(canonical, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(canonical, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("broken symlink %s", rel)
			}
			relTarget, err := filepath.Rel(canonical, target)
			if err != nil || strings.HasPrefix(relTarget, "..") || filepath.IsAbs(relTarget) {
				return fmt.Errorf("symlink %s escapes skill directory root", rel)
			}
			parts = append(parts, fmt.Sprintf("%s:%d:%o:symlink->%s", rel, info.Size(), info.Mode().Perm(), filepath.ToSlash(relTarget)))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported special directory entry %s", rel)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		parts = append(parts, fmt.Sprintf("%s:%d:%o:%s", rel, info.Size(), info.Mode().Perm(), hex.EncodeToString(sum[:])))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(parts)
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(digest[:]), nil
}
