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
	Generation     int
	CreatedAt      time.Time
	LastActivityAt time.Time
	ExpiresAt      time.Time
	HardExpiresAt  time.Time
}

// Store is the workspace metadata surface used by the runner.
type Store interface {
	Put(rec Record) error
	Get(id string) (Record, bool)
	ByIdempotency(ownerID, key string) (Record, bool)
	List(ownerID string) []Record
	UpdateStatus(id string, status Status) (Record, bool)
}

// Memory is a process-local store used until SQLite is wired.
type Memory struct {
	mu     sync.Mutex
	byID   map[string]*Record
	byIdem map[string]*Record
}

// NewMemory returns an empty in-process workspace store.
func NewMemory() *Memory {
	return &Memory{byID: map[string]*Record{}, byIdem: map[string]*Record{}}
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
