package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultWorkspaceRoot = "/workspace"

// Root is the canonical workspace directory. Env HARNESS_WORKSPACE_ROOT /
// CH_WORKSPACE_ROOT match the TypeScript worker.
func Root() string {
	raw := os.Getenv("HARNESS_WORKSPACE_ROOT")
	if raw == "" {
		raw = os.Getenv("CH_WORKSPACE_ROOT")
	}
	if raw == "" {
		raw = defaultWorkspaceRoot
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return filepath.Clean(raw)
	}
	return resolved
}

func normalizeRel(input string) (string, error) {
	if input == "" {
		input = "."
	}
	normalized := strings.ReplaceAll(input, "\\", "/")
	if strings.ContainsRune(normalized, 0) {
		return "", fmt.Errorf("path escapes workspace")
	}
	if strings.HasPrefix(normalized, "/") || drivePath(normalized) {
		return "", fmt.Errorf("path escapes workspace")
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return "", fmt.Errorf("path escapes workspace")
		}
	}
	return normalized, nil
}

func drivePath(p string) bool {
	if len(p) < 2 {
		return false
	}
	c := p[0]
	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) && p[1] == ':'
}

func confined(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	if candidate == root {
		return true
	}
	sep := string(os.PathSeparator)
	return strings.HasPrefix(candidate, root+sep)
}

// SafePath resolves input relative to the workspace root and rejects escapes,
// including symlink hops that leave the root.
func canonicalRoot(root string) string {
	if root == "" {
		root = Root()
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return filepath.Clean(root)
}

func SafePath(root, input string, allowMissing bool) (string, error) {
	root = canonicalRoot(root)
	rel, err := normalizeRel(input)
	if err != nil {
		return "", err
	}
	candidate := filepath.Clean(filepath.Join(root, rel))
	if !confined(root, candidate) {
		return "", fmt.Errorf("path escapes workspace")
	}
	if !allowMissing {
		actual, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", err
		}
		if !confined(root, actual) {
			return "", fmt.Errorf("symlink escapes workspace")
		}
		return actual, nil
	}
	ancestor := filepath.Dir(candidate)
	for confined(root, ancestor) {
		if actual, err := filepath.EvalSymlinks(ancestor); err == nil {
			if !confined(root, actual) {
				return "", fmt.Errorf("ancestor symlink escapes workspace")
			}
			if resolved, err := filepath.EvalSymlinks(candidate); err == nil {
				if !confined(root, resolved) {
					return "", fmt.Errorf("symlink escapes workspace")
				}
			} else if !os.IsNotExist(err) {
				return "", err
			}
			return candidate, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		if ancestor == root {
			break
		}
		next := filepath.Dir(ancestor)
		if next == ancestor {
			break
		}
		ancestor = next
	}
	return "", fmt.Errorf("directory ancestor is unavailable")
}

const (
	// MaxInternalOutput is the default command capture cap (1 MiB).
	MaxInternalOutput = 1_048_576
	// DefaultReadLimit is files_read's default page size.
	DefaultReadLimit = 65_536
)

// Truncate copies at most max bytes and reports whether the source was longer.
func Truncate(b []byte, max int) ([]byte, bool) {
	if max <= 0 {
		max = MaxInternalOutput
	}
	if len(b) <= max {
		return b, false
	}
	out := make([]byte, max)
	copy(out, b[:max])
	return out, true
}
