package typesafe

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const truncationMarker = "\n[TRUNCATED]"

var (
	bearerPattern = regexp.MustCompile(`\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*`)
	keyPattern    = regexp.MustCompile(`\b(?:sk|pk|ts|rk|ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{16,}`)
	jwtPattern    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
)

// Redaction is the fail-closed prompt transform. An unexpected snapshot shape
// must not send the original prompt.
type Redaction struct {
	Text      string
	Count     int
	Truncated bool
}

// RedactPrompt replaces known secret values and recognisable credential shapes,
// then truncates to the egress bound. Returning ok=false means send nothing.
func RedactPrompt(prompt string, secrets map[string]string, maxBytes int) (out Redaction, ok bool) {
	defer func() {
		if recover() != nil {
			out = Redaction{}
			ok = false
		}
	}()
	limit := maxBytes
	if limit <= 0 {
		limit = MaxEgressBytes
	}
	if limit > MaxEgressCeiling {
		limit = MaxEgressCeiling
	}
	count := 0
	names := make([]string, 0, len(secrets))
	for name, value := range secrets {
		if value == "" {
			continue
		}
		names = append(names, name)
		if strings.Contains(prompt, value) {
			count += strings.Count(prompt, value)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return len(secrets[names[i]]) > len(secrets[names[j]])
	})
	text := prompt
	for _, name := range names {
		value := secrets[name]
		if value == "" || !strings.Contains(text, value) {
			continue
		}
		text = strings.ReplaceAll(text, value, "[REDACTED_SECRET: "+name+"]")
	}
	text, n := replaceAllCount(bearerPattern, text, "[REDACTED_BEARER]")
	count += n
	text, n = replaceAllCount(keyPattern, text, "[REDACTED_KEY]")
	count += n
	text, n = replaceAllCount(jwtPattern, text, "[REDACTED_JWT]")
	count += n
	truncated := false
	if len(text) > limit {
		keep := limit - len(truncationMarker)
		if keep < 0 {
			keep = 0
		}
		for keep > 0 && !utf8.RuneStart(text[keep]) {
			keep--
		}
		text = text[:keep] + truncationMarker
		truncated = true
	}
	return Redaction{Text: text, Count: count, Truncated: truncated}, true
}

func replaceAllCount(re *regexp.Regexp, text, placeholder string) (string, int) {
	n := 0
	out := re.ReplaceAllStringFunc(text, func(string) string {
		n++
		return placeholder
	})
	return out, n
}
