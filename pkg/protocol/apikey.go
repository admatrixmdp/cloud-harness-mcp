package protocol

import "regexp"

const (
	PrefixAPIKey          = "apk"
	APIKeyMaxExpiryDays   = 3650
	apiKeyIDPattern       = `^apk_[A-Za-z0-9_-]{24}$`
	apiKeyValuePattern    = `^chm_key_apk_[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{43}$`
)

var (
	apiKeyIDRe    = regexp.MustCompile(apiKeyIDPattern)
	apiKeyValueRe = regexp.MustCompile(apiKeyValuePattern)
)

// ValidAPIKeyID reports whether id matches apk_ + 24 URL-safe chars.
func ValidAPIKeyID(id string) bool {
	return apiKeyIDRe.MatchString(id)
}

// ValidAPIKeyValue reports whether value matches the dashboard-issued key format.
func ValidAPIKeyValue(value string) bool {
	return len(value) <= 96 && apiKeyValueRe.MatchString(value)
}

// APIKeyState is the stored key lifecycle.
type APIKeyState string

const (
	APIKeyActive  APIKeyState = "ACTIVE"
	APIKeyExpired APIKeyState = "EXPIRED"
	APIKeyRevoked APIKeyState = "REVOKED"
)
