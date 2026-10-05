package protocol

import (
	"strings"
	"unicode"
)

// GitHubCredentialSecretNames may be injected as runtime secrets for workspace gh.
var GitHubCredentialSecretNames = []string{"GH_TOKEN", "GITHUB_TOKEN"}

var forbiddenSecretNames = map[string]struct{}{
	"PATH": {}, "HOME": {}, "SHELL": {}, "USER": {}, "LOGNAME": {},
	"GIT_CONFIG_NOSYSTEM": {}, "GIT_TERMINAL_PROMPT": {}, "AUTHORIZATION": {},
	"OWNER_ID": {}, "RUNNER_TOKEN": {}, "SECRET_KEYRING": {}, "SECRET_KEYRING_FILE": {},
	"STATE_DB": {}, "JOBS_ROOT": {}, "DOCKER_HOST": {}, "LD_PRELOAD": {},
	"LD_LIBRARY_PATH": {}, "BUILTIN_SKILLS_ROOT": {},
}

var forbiddenSecretPrefixes = []string{
	"HARNESS_", "CH_", "CLOUDFLARE_", "CF_", "GITHUB_APP_", "ACCESS_",
	"RUNNER_", "DOCKER_", "XDG_", "NPM_", "NPM_CONFIG_", "UV_", "BUN_",
	"PNPM_", "GIT_", "LD_",
}

const (
	MinSecretValueBytes         = 4
	MaxSecretValueBytes         = 65536
	MaxSecretDescriptionChars   = 500
)

// ValidateSecretName rejects reserved control-plane and toolchain names.
func ValidateSecretName(name string) error {
	name = strings.TrimSpace(name)
	if err := validateSecretNameShape(name); err != nil {
		return err
	}
	upper := strings.ToUpper(name)
	if _, ok := forbiddenSecretNames[upper]; ok {
		return errReservedSecretName
	}
	for _, prefix := range forbiddenSecretPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return errReservedSecretPrefix
		}
	}
	return nil
}

func validateSecretNameShape(name string) error {
	if len(name) < 1 || len(name) > 100 {
		return errInvalidSecretName
	}
	for i, r := range name {
		ok := r == '_' || unicode.IsLetter(r) || (i > 0 && unicode.IsDigit(r))
		if i == 0 && unicode.IsDigit(r) {
			ok = false
		}
		if !ok {
			return errInvalidSecretName
		}
	}
	return nil
}

type secretError string

func (e secretError) Error() string { return string(e) }

const (
	errInvalidSecretName     secretError = "secret name must be 1-100 characters and contain only letters, numbers, and underscores (starting with letter or underscore)"
	errReservedSecretName    secretError = "secret name is reserved for the control plane or system toolchains"
	errReservedSecretPrefix  secretError = "secret name uses reserved prefix"
	errSecretValueTooShort   secretError = "secret value must be at least 4 bytes to ensure reliable output redaction"
	errSecretValueTooLong    secretError = "secret value must not exceed 65536 bytes"
	errSecretValueBadChars   secretError = "secret value must not contain null or newline characters"
)

// ValidateSecretValue enforces size and character bounds without logging the value.
func ValidateSecretValue(value string) error {
	if strings.ContainsRune(value, 0) || strings.ContainsAny(value, "\n\r") {
		return errSecretValueBadChars
	}
	n := len(value)
	if n < MinSecretValueBytes {
		return errSecretValueTooShort
	}
	if n > MaxSecretValueBytes {
		return errSecretValueTooLong
	}
	return nil
}
