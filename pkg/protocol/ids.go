package protocol

import (
	"crypto/rand"
	"regexp"
)

// Opaque identifier prefixes from packages/contracts/src/identifiers.ts.
const (
	PrefixWorkspace             = "ws"
	PrefixOperation             = "op"
	PrefixShell                 = "sh"
	PrefixSession               = "sess"
	PrefixTask                  = "task"
	PrefixAgent                 = "agent"
	PrefixAgentLease            = "lease"
	PrefixAgentMessage          = "msg"
	PrefixModelCredential       = "cred"
	PrefixModelRevision         = "rev"
	PrefixSkillSource           = "sk"
	PrefixSkillRevision         = "skrev"
	PrefixSkillSet              = "skset"
	PrefixSkillImportJob        = "skjob"
	PrefixIntegrationCredential = "icr"
	PrefixProject               = "prj"
	PrefixEnvironment           = "env"
	PrefixSecret                = "sec"
	PrefixGlobalSecret          = "gsec"
	PrefixArtifact              = "art"
	PrefixAudit                 = "aud"
)

const opaqueAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

var (
	opaqueID       = regexp.MustCompile(`^[A-Za-z0-9_-]{20,80}$`)
	idempotencyKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	modelProfileID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)
)

// ValidOpaqueID reports whether value matches prefix_ + 20–80 URL-safe chars.
func ValidOpaqueID(prefix, value string) bool {
	want := prefix + "_"
	if len(value) < len(want)+20 || len(value) > len(want)+80 {
		return false
	}
	if value[:len(want)] != want {
		return false
	}
	return opaqueID.MatchString(value[len(want):])
}

// NewOpaqueID returns prefix_ + 24 random URL-safe characters.
func NewOpaqueID(prefix string) string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		panic("protocol: crypto/rand unavailable")
	}
	for i := range buf {
		buf[i] = opaqueAlphabet[int(buf[i])%len(opaqueAlphabet)]
	}
	return prefix + "_" + string(buf)
}

// ValidIdempotencyKey reports whether key matches IdempotencyKeySchema.
func ValidIdempotencyKey(key string) bool {
	return idempotencyKey.MatchString(key)
}

// ValidModelProfileID reports whether id matches ModelProfileIdSchema.
func ValidModelProfileID(id string) bool {
	return modelProfileID.MatchString(id)
}

// NetworkProfile is an executor egress profile.
// Only these two values are selectable; there is no raw bridge profile.
type NetworkProfile string

const (
	NetworkNone      NetworkProfile = "network-none"
	DependencyAccess NetworkProfile = "dependency-access"
)

// Valid reports whether p is a shipped executor network profile.
func (p NetworkProfile) Valid() bool {
	return p == NetworkNone || p == DependencyAccess
}
