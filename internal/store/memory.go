package store

import (
	"sync"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// Status is a workspace lifecycle state.
type Status string

const (
	StatusCreating           Status = "CREATING"
	StatusActive             Status = "ACTIVE"
	StatusClosed             Status = "CLOSED"
	StatusFailed             Status = "FAILED"
	StatusExpiredRecoverable Status = "EXPIRED_RECOVERABLE"
	StatusNetworkQuarantined Status = "NETWORK_QUARANTINED"
	StatusReaping            Status = "REAPING"
)

// Record is the public-ish workspace metadata row.
type Record struct {
	ID             string
	OwnerID        string
	RepositoryURL  string
	Ref            string
	Status         Status
	NetworkProfile protocol.NetworkProfile
	IdempotencyKey string
	Fingerprint    string
	ContainerName  string
	WorkspacePath  string
	EnvironmentID  string
	Generation     int
	CreatedAt      time.Time
	LastActivityAt time.Time
	ExpiresAt      time.Time
	HardExpiresAt  time.Time
	Error          string
}

// Store is the workspace metadata surface used by the runner.
type Store interface {
	Put(rec Record) error
	Get(id string) (Record, bool)
	ByIdempotency(ownerID, key string) (Record, bool)
	List(ownerID string) []Record
	UpdateStatus(id string, status Status) (Record, bool)
	RenewLease(id string, expiresAt, lastActivityAt time.Time) (Record, bool)
	Activate(id string, expiresAt, lastActivityAt time.Time) (Record, bool)
	SetPreferredWorkspace(ownerID, workspaceID string)
	PreferredWorkspace(ownerID string) (string, bool)
	SetGitIdentity(ownerID, name, email string)
	GitIdentity(ownerID string) (name, email string, ok bool)
	ClaimForReaping(id string, generation int, force bool) bool
	DefaultNetworkProfile() (protocol.NetworkProfile, bool)
	SetDefaultNetworkProfile(value *protocol.NetworkProfile, updatedAt time.Time)
}

// Memory is a process-local store used until SQLite is wired.
type Memory struct {
	mu             sync.Mutex
	byID           map[string]*Record
	byIdem         map[string]*Record
	preferred      map[string]string
	gitName        map[string]string
	gitEmail       map[string]string
	defaultProfile *protocol.NetworkProfile
}

// NewMemory returns an empty in-process workspace store.
func NewMemory() *Memory {
	return &Memory{
		byID:      map[string]*Record{},
		byIdem:    map[string]*Record{},
		preferred: map[string]string{},
		gitName:   map[string]string{},
		gitEmail:  map[string]string{},
	}
}

// Put inserts or replaces a record.
func (m *Memory) Put(rec Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := rec
	m.byID[rec.ID] = &cp
	if rec.IdempotencyKey != "" {
		m.byIdem[rec.OwnerID+"\x00"+rec.IdempotencyKey] = &cp
	}
	return nil
}

// Get returns a copy of the record.
func (m *Memory) Get(id string) (Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return Record{}, false
	}
	return *rec, true
}

// ByIdempotency returns the record for an owner+key pair.
func (m *Memory) ByIdempotency(ownerID, key string) (Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byIdem[ownerID+"\x00"+key]
	if !ok {
		return Record{}, false
	}
	return *rec, true
}

// List returns all records for an owner, newest first.
func (m *Memory) List(ownerID string) []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, 0)
	for _, rec := range m.byID {
		if ownerID == "" || rec.OwnerID == ownerID {
			out = append(out, *rec)
		}
	}
	return out
}

// UpdateStatus mutates status and activity time.
func (m *Memory) UpdateStatus(id string, status Status) (Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return Record{}, false
	}
	rec.Status = status
	rec.LastActivityAt = time.Now()
	if status == StatusClosed {
		rec.ContainerName = ""
	}
	return *rec, true
}

// RenewLease extends idle expiry without exceeding HardExpiresAt.
func (m *Memory) RenewLease(id string, expiresAt, lastActivityAt time.Time) (Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return Record{}, false
	}
	if rec.Status == StatusClosed || rec.Status == StatusFailed || rec.Status == StatusReaping {
		return *rec, false
	}
	if !expiresAt.Before(rec.HardExpiresAt) && !expiresAt.Equal(rec.HardExpiresAt) {
		expiresAt = rec.HardExpiresAt
	}
	rec.ExpiresAt = expiresAt
	rec.LastActivityAt = lastActivityAt
	if rec.Status == StatusExpiredRecoverable {
		rec.Status = StatusActive
	}
	return *rec, true
}

// Activate returns an idle-expired or quarantined workspace to ACTIVE.
func (m *Memory) Activate(id string, expiresAt, lastActivityAt time.Time) (Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return Record{}, false
	}
	switch rec.Status {
	case StatusActive, StatusExpiredRecoverable, StatusNetworkQuarantined:
	default:
		return *rec, false
	}
	if expiresAt.After(rec.HardExpiresAt) {
		expiresAt = rec.HardExpiresAt
	}
	rec.Status = StatusActive
	rec.ExpiresAt = expiresAt
	rec.LastActivityAt = lastActivityAt
	return *rec, true
}

// SetPreferredWorkspace stores the owner default used when workspaceId is omitted.
func (m *Memory) SetPreferredWorkspace(ownerID, workspaceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.preferred[ownerID] = workspaceID
}

// PreferredWorkspace returns the owner default.
func (m *Memory) PreferredWorkspace(ownerID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.preferred[ownerID]
	return id, ok && id != ""
}

// SetGitIdentity stores the owner commit identity.
func (m *Memory) SetGitIdentity(ownerID, name, email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gitName[ownerID] = name
	m.gitEmail[ownerID] = email
}

// GitIdentity returns the owner commit identity.
func (m *Memory) GitIdentity(ownerID string) (string, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name, ok := m.gitName[ownerID]
	if !ok {
		return "", "", false
	}
	return name, m.gitEmail[ownerID], true
}

var reapingStatuses = map[Status]struct{}{
	StatusCreating:           {},
	StatusActive:             {},
	StatusFailed:             {},
	StatusExpiredRecoverable: {},
	StatusNetworkQuarantined: {},
}

// ClaimForReaping fences a workspace into REAPING and bumps generation.
func (m *Memory) ClaimForReaping(id string, generation int, force bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok || rec.Generation != generation {
		return false
	}
	if _, allowed := reapingStatuses[rec.Status]; !allowed {
		return false
	}
	_ = force
	rec.Status = StatusReaping
	rec.Generation++
	rec.LastActivityAt = time.Now()
	return true
}

// DefaultNetworkProfile is the operator-selected instance default, if any.
func (m *Memory) DefaultNetworkProfile() (protocol.NetworkProfile, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.defaultProfile == nil {
		return "", false
	}
	return *m.defaultProfile, true
}

// SetDefaultNetworkProfile persists the operator default, or clears it with nil.
func (m *Memory) SetDefaultNetworkProfile(value *protocol.NetworkProfile, updatedAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = updatedAt
	if value == nil {
		m.defaultProfile = nil
		return
	}
	cp := *value
	m.defaultProfile = &cp
}
