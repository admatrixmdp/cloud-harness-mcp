package executor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func confinedGrep(ctx context.Context, root, target, pattern, glob string, maxResults, maxBytes int) ([]string, bool, error) {
	if maxResults <= 0 {
		maxResults = 100
	}
	if maxBytes <= 0 {
		maxBytes = 262144
	}
	if glob != "" {
		if strings.Contains(glob, "..") || strings.ContainsRune(glob, 0) || strings.HasPrefix(glob, "/") {
			return nil, false, fmt.Errorf("glob escapes workspace")
		}
	}
	root = canonicalRoot(root)
	matches := make([]string, 0, maxResults)
	bytesUsed := 0
	truncated := false
	err := filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil
		}
		if glob != "" {
			base := filepath.Base(path)
			ok, _ := filepath.Match(glob, base)
			if !ok {
				ok, _ = filepath.Match(glob, rel)
			}
			if !ok {
				return nil
			}
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		lineNo := 0
		fileHits := 0
		for scanner.Scan() {
			lineNo++
			text := scanner.Text()
			col := strings.Index(text, pattern)
			if col < 0 {
				continue
			}
			entry := fmt.Sprintf("%s:%d:%d:%s", filepath.ToSlash(rel), lineNo, col+1, text)
			matches = append(matches, entry)
			bytesUsed += len(entry) + 1
			fileHits++
			if len(matches) >= maxResults || bytesUsed >= maxBytes {
				truncated = true
				return filepath.SkipAll
			}
		}
		_ = fileHits
		return nil
	})
	if err == filepath.SkipAll {
		err = nil
	}
	return matches, truncated, err
}
