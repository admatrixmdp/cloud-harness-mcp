package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"
)

var (
	agentIDRe = regexp.MustCompile(`^agent_[A-Za-z0-9_-]{20,80}$`)
	leaseIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	leaseRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{43,256}$`)
)

// ProfileLimits is the budget cap copied from a gateway profile.
type ProfileLimits struct {
	MaxInputTokens  int
	MaxOutputTokens int
	MaxCostMicros   int64
}

// Profile is the subset of a gateway profile the lease layer needs.
type Profile struct {
	ID                     string
	Model                  string
	DownstreamPath         string
	InputMicrosPerMillion  int64
	OutputMicrosPerMillion int64
	Limits                 ProfileLimits
	Upstream               Upstream
}

// IssueInput is the control-plane request that mints a one-time lease token.
type IssueInput struct {
	LeaseID         string
	AgentID         string
	ProfileID       string
	TTL             time.Duration
	MaxInputTokens  int
	MaxOutputTokens int
	MaxCostMicros   int64
}

// Grant is the live budget binding for one agent/profile pair.
type Grant struct {
	AgentID               string
	ProfileID             string
	ExpiresAt             time.Time
	RemainingInputTokens  int
	RemainingOutputTokens int
	RemainingCostMicros   int64
	key                   string
}

// Registry stores opaque lease tokens hashed at rest.
type Registry struct {
	mu         sync.Mutex
	pending    map[string]Grant
	active     map[string]Grant
	used       map[string]time.Time
	keyByID    map[string]string
	idByKey    map[string]string
	maxEntries int
	now        func() time.Time
}

// NewRegistry returns an empty lease registry.
func NewRegistry() *Registry {
	return &Registry{
		pending:    map[string]Grant{},
		active:     map[string]Grant{},
		used:       map[string]time.Time{},
		keyByID:    map[string]string{},
		idByKey:    map[string]string{},
		maxEntries: 10_000,
		now:        time.Now,
	}
}

// Issue mints a random lease token. The token is never stored in plaintext.
func (r *Registry) Issue(input IssueInput, profile Profile) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	if len(r.pending)+len(r.active)+len(r.used) >= r.maxEntries {
		return "", fmt.Errorf("lease capacity reached")
	}
	if !leaseIDRe.MatchString(input.LeaseID) {
		return "", fmt.Errorf("leaseId is invalid")
	}
	if _, exists := r.keyByID[input.LeaseID]; exists {
		return "", fmt.Errorf("leaseId already registered")
	}
	if !agentIDRe.MatchString(input.AgentID) {
		return "", fmt.Errorf("agentId is invalid")
	}
	if input.ProfileID != profile.ID {
		return "", fmt.Errorf("profile mismatch")
	}
	ttl := input.TTL
	if ttl < time.Second || ttl > 24*time.Hour {
		return "", fmt.Errorf("ttlMs is out of bounds")
	}
	token := randomLease()
	key := hashLease(token)
	for r.pending[key].AgentID != "" || r.active[key].AgentID != "" || !r.used[key].IsZero() {
		token = randomLease()
		key = hashLease(token)
	}
	grant := Grant{
		AgentID:               input.AgentID,
		ProfileID:             input.ProfileID,
		ExpiresAt:             r.now().Add(ttl),
		RemainingInputTokens:  clampLimit(boundInt(input.MaxInputTokens, 1, 10_000_000), profile.Limits.MaxInputTokens),
		RemainingOutputTokens: clampLimit(boundInt(input.MaxOutputTokens, 1, 2_000_000), profile.Limits.MaxOutputTokens),
		RemainingCostMicros:   clampLimit64(boundInt64(input.MaxCostMicros, 0, 1_000_000_000_000), profile.Limits.MaxCostMicros),
		key:                   key,
	}
	r.pending[key] = grant
	r.keyByID[input.LeaseID] = key
	r.idByKey[key] = input.LeaseID
	return token, nil
}

// Consume activates a pending lease (or reuses an active one) for the bound agent/profile.
func (r *Registry) Consume(token, agentID, profileID string) (Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	if !leaseRe.MatchString(token) {
		return Grant{}, fmt.Errorf("invalid lease")
	}
	key := hashLease(token)
	grant, pending := r.pending[key]
	if !pending {
		grant, pending = r.active[key]
		if !pending {
			if usedEqual(r.used, key) {
				return Grant{}, fmt.Errorf("lease revoked or expired")
			}
			return Grant{}, fmt.Errorf("invalid lease")
		}
	}
	if !grant.ExpiresAt.After(r.now()) {
		delete(r.pending, key)
		delete(r.active, key)
		r.used[key] = r.now()
		return Grant{}, fmt.Errorf("lease expired")
	}
	if grant.AgentID != agentID || grant.ProfileID != profileID {
		return Grant{}, fmt.Errorf("lease binding mismatch")
	}
	if _, ok := r.pending[key]; ok {
		delete(r.pending, key)
		r.active[key] = grant
	}
	grant.key = key
	return grant, nil
}

// ApplyReservation writes remaining budgets back onto the active lease.
func (r *Registry) ApplyReservation(grant Grant) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if grant.key == "" {
		return
	}
	if cur, ok := r.active[grant.key]; ok {
		cur.RemainingInputTokens = grant.RemainingInputTokens
		cur.RemainingOutputTokens = grant.RemainingOutputTokens
		cur.RemainingCostMicros = grant.RemainingCostMicros
		r.active[grant.key] = cur
	}
}

// Revoke marks a lease unusable. Replay of the hashed token is rejected.
func (r *Registry) Revoke(leaseID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key, ok := r.keyByID[leaseID]
	if !ok {
		return false
	}
	_, pending := r.pending[key]
	_, active := r.active[key]
	delete(r.pending, key)
	delete(r.active, key)
	delete(r.keyByID, leaseID)
	delete(r.idByKey, key)
	r.used[key] = r.now()
	r.pruneLocked()
	return pending || active
}

// ActiveCount is pending + in-flight leases.
func (r *Registry) ActiveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	return len(r.pending) + len(r.active)
}

func (r *Registry) pruneLocked() {
	now := r.now()
	for key, grant := range r.pending {
		if !grant.ExpiresAt.After(now) {
			delete(r.pending, key)
			r.dropID(key)
			r.used[key] = now
		}
	}
	for key, grant := range r.active {
		if !grant.ExpiresAt.After(now) {
			delete(r.active, key)
			r.dropID(key)
			r.used[key] = now
		}
	}
	horizon := now.Add(-24 * time.Hour)
	for key, usedAt := range r.used {
		if usedAt.Before(horizon) {
			delete(r.used, key)
		}
	}
}

func (r *Registry) dropID(key string) {
	if id, ok := r.idByKey[key]; ok {
		delete(r.keyByID, id)
	}
	delete(r.idByKey, key)
}

func usedEqual(used map[string]time.Time, key string) bool {
	if _, ok := used[key]; ok {
		return true
	}
	want, err := hex.DecodeString(key)
	if err != nil {
		return false
	}
	for stored := range used {
		got, err := hex.DecodeString(stored)
		if err != nil || len(got) != len(want) {
			continue
		}
		if subtle.ConstantTimeCompare(got, want) == 1 {
			return true
		}
	}
	return false
}

func randomLease() string {
	b := make([]byte, 48)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashLease(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func boundInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func boundInt64(v, min, max int64) int64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func clampLimit(v, cap int) int {
	if cap <= 0 {
		return v
	}
	return minInt(v, cap)
}

func clampLimit64(v, cap int64) int64 {
	if cap <= 0 {
		return v
	}
	return minInt64(v, cap)
}

// ValidAgentID reports whether id matches the opaque agent_ prefix.
func ValidAgentID(id string) bool { return agentIDRe.MatchString(id) }
