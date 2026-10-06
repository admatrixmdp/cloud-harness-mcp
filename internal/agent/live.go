package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
)

// SnapshotCredential is one decrypted provider secret for apply_snapshot.
// Callers must not log Secret.
type SnapshotCredential struct {
	Provider string `json:"provider"`
	AuthMode string `json:"authMode"`
	Secret   string `json:"secret"`
}

// Snapshot is the runner→gateway control payload. Secrets never appear in MCP results.
type Snapshot struct {
	Sequence    int
	Generation  int
	Credentials map[string]SnapshotCredential
	Profiles    map[string]json.RawMessage
}

type liveCred struct {
	Provider string
	AuthMode string
	Secret   string
}

// LiveRegistry is the in-RAM dynamic profile/credential table the Unix control
// plane mutates. HTTP lease lookup reads the same pointer.
type LiveRegistry struct {
	mu             sync.RWMutex
	profiles       map[string]Profile
	credentials    map[string]liveCred
	snapshotDigest string
	bootID         string
	allowPrivate   bool
}

// NewLiveRegistry allocates a boot id. Credentials stay in this process only.
func NewLiveRegistry(allowPrivate bool) *LiveRegistry {
	var buf [12]byte
	_, _ = rand.Read(buf[:])
	return &LiveRegistry{
		profiles:     map[string]Profile{},
		credentials:  map[string]liveCred{},
		bootID:       "boot_" + hex.EncodeToString(buf[:]),
		allowPrivate: allowPrivate,
	}
}

// Profile returns a live (snapshot) profile, if present.
func (r *LiveRegistry) Profile(id string) (Profile, bool) {
	if r == nil {
		return Profile{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[id]
	return p, ok
}

func (r *LiveRegistry) digestLocked() ControlDigest {
	return ControlDigest{
		GatewayBootID:         r.bootID,
		SnapshotDigest:        r.snapshotDigest,
		ActiveProfileCount:    len(r.profiles),
		ActiveCredentialCount: len(r.credentials),
	}
}

// Digest is the control-plane status payload. Secrets are never included.
func (r *LiveRegistry) Digest(activeLeases int) ControlDigest {
	if r == nil {
		return ControlDigest{ActiveLeaseCount: activeLeases}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	d := r.digestLocked()
	d.ActiveLeaseCount = activeLeases
	return d
}

func (r *LiveRegistry) apply(snap Snapshot, record []byte) (ControlAck, error) {
	if r == nil {
		return ControlAck{}, fmt.Errorf("dynamic gateway registry is unavailable")
	}
	pendingCreds := make(map[string]liveCred, len(snap.Credentials))
	for id, cred := range snap.Credentials {
		auth := cred.AuthMode
		if auth != "x-api-key" {
			auth = "authorization"
		}
		pendingCreds[id] = liveCred{Provider: cred.Provider, AuthMode: auth, Secret: cred.Secret}
	}
	pendingProfiles := make(map[string]Profile, len(snap.Profiles))
	r.mu.Lock()
	defer r.mu.Unlock()
	for revID, raw := range snap.Profiles {
		var rev snapshotRevision
		if err := json.Unmarshal(raw, &rev); err != nil {
			return ControlAck{}, fmt.Errorf("invalid profile revision %s", revID)
		}
		cred, ok := pendingCreds[rev.CredentialID]
		if !ok {
			cred, ok = r.credentials[rev.CredentialID]
		}
		if !ok || cred.Secret == "" {
			return ControlAck{}, fmt.Errorf("unresolved credential binding for profile revision %s", revID)
		}
		profile, err := revisionProfile(revID, rev, cred, r.allowPrivate)
		if err != nil {
			return ControlAck{}, err
		}
		pendingProfiles[revID] = profile
	}
	for id, cred := range pendingCreds {
		r.credentials[id] = cred
	}
	for id, profile := range pendingProfiles {
		r.profiles[id] = profile
	}
	sum := sha256Hex(record)
	r.snapshotDigest = "sha256:" + sum
	seq := snap.Sequence
	if seq <= 0 {
		seq = 1
	}
	gen := snap.Generation
	if gen <= 0 {
		gen = 1
	}
	return ControlAck{
		Type:                  "ack",
		Sequence:              seq,
		Generation:            gen,
		GatewayBootID:         r.bootID,
		SnapshotDigest:        r.snapshotDigest,
		ActiveProfileCount:    len(r.profiles),
		ActiveCredentialCount: len(r.credentials),
	}, nil
}

type snapshotRevision struct {
	CredentialID   string `json:"credentialId"`
	Model          string `json:"model"`
	DownstreamPath string `json:"downstreamPath"`
	UpstreamURL    string `json:"upstreamUrl"`
	Pricing        struct {
		InputMicrosPerMillionTokens  int64 `json:"inputMicrosPerMillionTokens"`
		OutputMicrosPerMillionTokens int64 `json:"outputMicrosPerMillionTokens"`
	} `json:"pricing"`
	Limits struct {
		MaxInputTokens  int   `json:"maxInputTokens"`
		MaxOutputTokens int   `json:"maxOutputTokens"`
		MaxCostMicros   int64 `json:"maxCostMicros"`
	} `json:"limits"`
}

func revisionProfile(revID string, rev snapshotRevision, cred liveCred, allowPrivate bool) (Profile, error) {
	upstreamRaw := strings.TrimSpace(rev.UpstreamURL)
	if upstreamRaw == "" {
		upstreamRaw = "https://api.openai.com/v1/chat/completions"
	}
	parsed, err := url.Parse(upstreamRaw)
	if err != nil || parsed.Host == "" {
		return Profile{}, fmt.Errorf("invalid upstream URL")
	}
	if !allowPrivate {
		if err := AssertProductionHostname(parsed.Hostname()); err != nil {
			return Profile{}, err
		}
	}
	header := "Authorization"
	scheme := "Bearer"
	if cred.AuthMode == "x-api-key" {
		header = "x-api-key"
		scheme = ""
	}
	model := rev.Model
	if model == "" {
		model = "default"
	}
	path := rev.DownstreamPath
	if path == "" {
		path = "/v1/chat/completions"
	}
	limits := ProfileLimits{MaxInputTokens: 400_000, MaxOutputTokens: 128_000, MaxCostMicros: 100_000_000}
	if rev.Limits.MaxInputTokens > 0 {
		limits.MaxInputTokens = rev.Limits.MaxInputTokens
	}
	if rev.Limits.MaxOutputTokens > 0 {
		limits.MaxOutputTokens = rev.Limits.MaxOutputTokens
	}
	if rev.Limits.MaxCostMicros > 0 {
		limits.MaxCostMicros = rev.Limits.MaxCostMicros
	}
	return Profile{
		ID:                     revID,
		Provider:               model,
		Model:                  model,
		DownstreamPath:         path,
		InputMicrosPerMillion:  rev.Pricing.InputMicrosPerMillionTokens,
		OutputMicrosPerMillion: rev.Pricing.OutputMicrosPerMillionTokens,
		Limits:                 limits,
		Upstream: Upstream{
			URL:              parsed.String(),
			Credential:       cred.Secret,
			CredentialHeader: header,
			CredentialScheme: scheme,
			AllowPrivate:     allowPrivate,
		},
	}, nil
}

// AssertProductionHostname rejects private, reserved, and non-public upstreams.
func AssertProductionHostname(hostname string) error {
	lower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	unsafeSuffixes := []string{".localhost", ".local", ".internal", ".home", ".lan", ".corp", ".test", ".invalid", ".example", ".arpa"}
	if lower == "localhost" || lower == "metadata.google.internal" || !strings.Contains(lower, ".") {
		return fmt.Errorf("production upstream hostname is private or non-public")
	}
	for _, suffix := range unsafeSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return fmt.Errorf("production upstream hostname is private or non-public")
		}
	}
	if ip := net.ParseIP(lower); ip != nil && git.AddressForbidden(lower) {
		return fmt.Errorf("production upstream address is private or reserved")
	}
	return nil
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
