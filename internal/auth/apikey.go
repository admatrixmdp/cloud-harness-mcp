package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// ParseAPIKey splits chm_key_<id>.<secret> without logging the secret.
func ParseAPIKey(value string) (id, secret string, ok bool) {
	if !protocol.ValidAPIKeyValue(value) {
		return "", "", false
	}
	without := strings.TrimPrefix(value, "chm_key_")
	id, secret, found := strings.Cut(without, ".")
	if !found || !protocol.ValidAPIKeyID(id) || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// HashSecret is the stored SHA-256 of the secret half. Never log value.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// VerifySecret compares a presented secret to a stored hash.
func VerifySecret(secret string, storedHash []byte) bool {
	got := HashSecret(secret)
	if len(storedHash) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare(got, storedHash) == 1
}

// DisplayPrefix is the dashboard-visible prefix; it must not contain the secret.
func DisplayPrefix(id string) string {
	if len(id) < 12 {
		return "chm_key_apk_…"
	}
	return "chm_key_" + id[:12] + "…"
}

// LogKeyEvent records a key lifecycle event without the raw credential.
func LogKeyEvent(action, keyID string) {
	slog.Info("api_key", "action", action, "keyId", keyID)
}

// EncodeRandom is a helper for tests constructing key material.
func EncodeRandom(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
