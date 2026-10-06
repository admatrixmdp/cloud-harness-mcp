package typesafe

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"unicode/utf8"
)

const rosterEllipsis = "\u2026"

// RosterFromSkills turns executor skill files into the TypeSafe ranking roster.
// Frontmatter is treated as data, never as instructions.
func RosterFromSkills(entries []SkillFile) (roster []RosterEntry, digest string) {
	roster = make([]RosterEntry, 0, len(entries))
	for _, skill := range entries {
		content := ""
		if skill.File != "" {
			info, err := os.Stat(skill.File)
			if err == nil && info.Mode().IsRegular() && info.Size() <= RosterFileMaxBytes {
				raw, err := os.ReadFile(skill.File)
				if err == nil {
					content = string(raw)
				}
			}
		}
		description, body := parseSkillDocument(content)
		fallback := firstProseLine(body)
		if fallback == "" {
			fallback = skill.Name
		}
		source := description
		if source == "" {
			source = fallback
		}
		roster = append(roster, RosterEntry{
			Name:             skill.Name,
			Source:           skill.Source,
			ContentSHA256:    skill.ContentSHA256,
			IndexDescription: boundRosterText(source, IndexDescriptionMax),
			DescriptionFull:  boundRosterText(source, DescriptionFullMax),
			BodyExcerpt:      boundRosterText(body, BodyExcerptMax),
		})
	}
	parts := make([]string, 0, len(roster))
	for _, entry := range roster {
		parts = append(parts, strings.Join([]string{entry.Name, entry.Source, entry.ContentSHA256, entry.IndexDescription}, "\x00"))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return roster, hex.EncodeToString(sum[:])
}

// SkillFile is the executor-facing skill inventory row.
type SkillFile struct {
	Name          string
	Source        string
	File          string
	ContentSHA256 string
}

func stripControlCharacters(text string) string {
	out := make([]rune, 0, utf8.RuneCountInString(text))
	for _, r := range text {
		code := r
		if code == 9 || code == 10 || code == 13 || (code >= 32 && code != 127) {
			out = append(out, r)
		}
	}
	return string(out)
}

func boundRosterText(text string, max int) string {
	cleaned := strings.TrimSpace(stripControlCharacters(text))
	if utf8.RuneCountInString(cleaned) <= max {
		return cleaned
	}
	runes := []rune(cleaned)
	keep := max - 1
	if keep < 0 {
		keep = 0
	}
	return string(runes[:keep]) + rosterEllipsis
}

func parseSkillDocument(content string) (description, body string) {
	text := stripControlCharacters(content)
	if strings.HasPrefix(text, "---\n") || strings.HasPrefix(text, "---\r\n") {
		rest := text[3:]
		if strings.HasPrefix(rest, "\r\n") {
			rest = rest[2:]
		} else if strings.HasPrefix(rest, "\n") {
			rest = rest[1:]
		}
		end := strings.Index(rest, "\n---")
		if end >= 0 {
			frontmatter := rest[:end]
			body = rest[end+4:]
			if strings.HasPrefix(body, "\n") {
				body = body[1:]
			} else if strings.HasPrefix(body, "\r\n") {
				body = body[2:]
			}
			for _, line := range strings.Split(frontmatter, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(trimmed), "description:") {
					value := strings.TrimSpace(trimmed[len("description:"):])
					value = strings.Trim(value, `"'`)
					return value, body
				}
			}
			return "", body
		}
	}
	return "", text
}

func firstProseLine(body string) string {
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "---") {
			continue
		}
		return trimmed
	}
	return ""
}
