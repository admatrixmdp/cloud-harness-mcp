package mcpgw

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	minSecretChars      = 4
	maxStoredErrorChars = 500
	redactedHeaderValue = "[REDACTED]"
	redactedSecretValue = "[REDACTED_SECRET]"
)

// credentialHeaderLine redacts the value of a credential-shaped header while
// keeping the header name. Matches today apps/runner mcp-gateway-store.
var credentialHeaderLine = regexp.MustCompile(`(?im)^(\s*(?:authorization|cookie|set-cookie|x-api-key|proxy-authorization)\s*:\s*).*$`)

// ScrubCredentialText strips credential-shaped header lines and every known
// encoding of a secret (raw, base64, base64url, hex, percent). The API must
// always pass an empty secrets array on the wire; this is defence in depth for
// runner-local tests.
func ScrubCredentialText(text string, secrets []string) string {
	out := credentialHeaderLine.ReplaceAllString(text, "${1}"+redactedHeaderValue)
	forms := make([]string, 0)
	seen := map[string]struct{}{}
	for _, secret := range secrets {
		if len(secret) < minSecretChars {
			continue
		}
		for _, form := range secretForms(secret) {
			if _, ok := seen[form]; ok {
				continue
			}
			seen[form] = struct{}{}
			forms = append(forms, form)
		}
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	for _, form := range forms {
		out = strings.ReplaceAll(out, form, redactedSecretValue)
	}
	return out
}

func secretForms(secret string) []string {
	raw := []byte(secret)
	percent := encodeURIComponent(secret)
	candidates := []string{
		secret,
		base64.StdEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
		hex.EncodeToString(raw),
		strings.ToUpper(hex.EncodeToString(raw)),
		percent,
		strings.ToLower(percent),
	}
	out := make([]string, 0, len(candidates))
	for _, form := range candidates {
		if len(form) >= minSecretChars {
			out = append(out, form)
		}
	}
	return out
}

func encodeURIComponent(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func scrubStoredError(message string, secrets []string) any {
	if strings.TrimSpace(message) == "" {
		return nil
	}
	out := ScrubCredentialText(message, secrets)
	if len(out) > maxStoredErrorChars {
		out = out[:maxStoredErrorChars]
	}
	return out
}
