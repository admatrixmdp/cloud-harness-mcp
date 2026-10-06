package store

import (
	"database/sql"
	"encoding/json"
	"sync"
	"time"
)

// GitOpKind is a durable git mutation covered by the idempotency ledger.
type GitOpKind string

const (
	GitOpPush     GitOpKind = "push"
	GitOpCommit   GitOpKind = "commit"
	GitOpFinalize GitOpKind = "finalize"
)

// GitOpStatus is the ledger row lifecycle.
type GitOpStatus string

const (
	GitOpPending            GitOpStatus = "PENDING"
	GitOpSucceeded          GitOpStatus = "SUCCEEDED"
	GitOpUnknownRemoteState GitOpStatus = "UNKNOWN_REMOTE_STATE"
	GitOpConflict           GitOpStatus = "CONFLICT"
	GitOpFailed             GitOpStatus = "FAILED"
)

// GitOpRecord is one git_operation_idempotency row.
type GitOpRecord struct {
	OwnerID            string
	WorkspaceID        string
	IdempotencyKey     string
	Operation          GitOpKind
	RequestFingerprint string
	TargetRef          string
	ExpectedRemoteOID  string
	LocalCommitSHA     string
	Status             GitOpStatus
	ResultJSON         string
	ErrorJSON          string
	CreatedAt          time.Time
	FinishedAt         time.Time
}

// GitOpAction is the outcome of AcquireGitOp.
type GitOpAction string

const (
	GitOpAcquired            GitOpAction = "ACQUIRED"
	GitOpReplaySucceeded     GitOpAction = "REPLAY_SUCCEEDED"
	GitOpFingerprintConflict GitOpAction = "FINGERPRINT_CONFLICT"
	GitOpInFlight            GitOpAction = "IN_FLIGHT"
	GitOpReconcileRequired   GitOpAction = "RECONCILE_REQUIRED"
)

// GitOpStore is the durable git mutation ledger.
type GitOpStore interface {
	AcquireGitOp(rec GitOpRecord) (GitOpAction, GitOpRecord)
	FinishGitOp(ownerID, workspaceID, key string, status GitOpStatus, resultJSON, errorJSON, localSHA string) bool
}

const gitOpDDL = `
CREATE TABLE IF NOT EXISTS git_operation_idempotency (
  owner_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN ('push', 'commit', 'finalize')),
  request_fingerprint TEXT NOT NULL,
  target_ref TEXT,
  expected_remote_oid TEXT,
  local_commit_sha TEXT,
  status TEXT NOT NULL CHECK(status IN ('PENDING', 'SUCCEEDED', 'UNKNOWN_REMOTE_STATE', 'CONFLICT', 'FAILED')),
  result_json TEXT,
  error_json TEXT,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  PRIMARY KEY(owner_id, workspace_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS git_op_idempotency_lookup ON git_operation_idempotency(owner_id, workspace_id, operation, created_at DESC);
CREATE TABLE IF NOT EXISTS finalize_idempotency (
  owner_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(owner_id, workspace_id, idempotency_key)
);
`

func ensureGitOpSchema(db *sql.DB) error {
	_, err := db.Exec(gitOpDDL)
	return err
}

func (s *SQLite) AcquireGitOp(rec GitOpRecord) (GitOpAction, GitOpRecord) {
	if err := ensureGitOpSchema(s.db); err != nil {
		return GitOpReconcileRequired, rec
	}
	tx, err := s.db.Begin()
	if err != nil {
		return GitOpReconcileRequired, rec
	}
	defer func() { _ = tx.Rollback() }()
	existing, ok := getGitOpTx(tx, rec.OwnerID, rec.WorkspaceID, rec.IdempotencyKey)
	if !ok {
		if rec.Operation == GitOpFinalize {
			if legacy, found := getLegacyFinalizeTx(tx, rec.OwnerID, rec.WorkspaceID, rec.IdempotencyKey); found {
				_, _ = tx.Exec(`INSERT INTO git_operation_idempotency
					(owner_id, workspace_id, idempotency_key, operation, request_fingerprint, status, result_json, created_at, finished_at)
					VALUES (?, ?, ?, 'finalize', '', 'SUCCEEDED', ?, ?, ?)`,
					rec.OwnerID, rec.WorkspaceID, rec.IdempotencyKey, legacy.ResultJSON, legacy.CreatedAt.UnixMilli(), legacy.CreatedAt.UnixMilli())
				_ = tx.Commit()
				legacy.Operation = GitOpFinalize
				legacy.Status = GitOpSucceeded
				return GitOpReplaySucceeded, legacy
			}
		}
		now := rec.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}
		_, err := tx.Exec(`INSERT INTO git_operation_idempotency
			(owner_id, workspace_id, idempotency_key, operation, request_fingerprint, target_ref, expected_remote_oid, local_commit_sha, status, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)`,
			rec.OwnerID, rec.WorkspaceID, rec.IdempotencyKey, string(rec.Operation), rec.RequestFingerprint,
			nullString(rec.TargetRef), nullString(rec.ExpectedRemoteOID), nullString(rec.LocalCommitSHA), now.UnixMilli())
		if err != nil {
			return GitOpReconcileRequired, rec
		}
		_ = tx.Commit()
		rec.Status = GitOpPending
		rec.CreatedAt = now
		return GitOpAcquired, rec
	}
	_ = tx.Commit()
	if existing.Operation != rec.Operation {
		return GitOpFingerprintConflict, existing
	}
	if existing.Operation == GitOpFinalize && existing.Status == GitOpSucceeded && existing.RequestFingerprint == "" {
		return GitOpReplaySucceeded, existing
	}
	if existing.RequestFingerprint != rec.RequestFingerprint {
		return GitOpFingerprintConflict, existing
	}
	if existing.Status == GitOpSucceeded {
		return GitOpReplaySucceeded, existing
	}
	if existing.Status == GitOpPending {
		return GitOpInFlight, existing
	}
	return GitOpReconcileRequired, existing
}

func (s *SQLite) FinishGitOp(ownerID, workspaceID, key string, status GitOpStatus, resultJSON, errorJSON, localSHA string) bool {
	if err := ensureGitOpSchema(s.db); err != nil {
		return false
	}
	res, err := s.db.Exec(`UPDATE git_operation_idempotency
		SET status = ?, result_json = COALESCE(?, result_json), error_json = COALESCE(?, error_json),
		    local_commit_sha = COALESCE(?, local_commit_sha), finished_at = ?
		WHERE owner_id = ? AND workspace_id = ? AND idempotency_key = ?`,
		string(status), nullString(resultJSON), nullString(errorJSON), nullString(localSHA),
		time.Now().UTC().UnixMilli(), ownerID, workspaceID, key)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func getGitOpTx(tx *sql.Tx, ownerID, workspaceID, key string) (GitOpRecord, bool) {
	row := tx.QueryRow(`SELECT owner_id, workspace_id, idempotency_key, operation, request_fingerprint,
		IFNULL(target_ref,''), IFNULL(expected_remote_oid,''), IFNULL(local_commit_sha,''), status,
		IFNULL(result_json,''), IFNULL(error_json,''), created_at, IFNULL(finished_at,0)
		FROM git_operation_idempotency WHERE owner_id = ? AND workspace_id = ? AND idempotency_key = ?`,
		ownerID, workspaceID, key)
	return scanGitOp(row)
}

func getLegacyFinalizeTx(tx *sql.Tx, ownerID, workspaceID, key string) (GitOpRecord, bool) {
	row := tx.QueryRow(`SELECT owner_id, workspace_id, idempotency_key, result_json, created_at
		FROM finalize_idempotency WHERE owner_id = ? AND workspace_id = ? AND idempotency_key = ?`,
		ownerID, workspaceID, key)
	var rec GitOpRecord
	var created int64
	if err := row.Scan(&rec.OwnerID, &rec.WorkspaceID, &rec.IdempotencyKey, &rec.ResultJSON, &created); err != nil {
		return GitOpRecord{}, false
	}
	rec.CreatedAt = time.UnixMilli(created).UTC()
	rec.FinishedAt = rec.CreatedAt
	return rec, true
}

func scanGitOp(row *sql.Row) (GitOpRecord, bool) {
	var rec GitOpRecord
	var created, finished int64
	var op, status string
	if err := row.Scan(&rec.OwnerID, &rec.WorkspaceID, &rec.IdempotencyKey, &op, &rec.RequestFingerprint,
		&rec.TargetRef, &rec.ExpectedRemoteOID, &rec.LocalCommitSHA, &status,
		&rec.ResultJSON, &rec.ErrorJSON, &created, &finished); err != nil {
		return GitOpRecord{}, false
	}
	rec.Operation = GitOpKind(op)
	rec.Status = GitOpStatus(status)
	rec.CreatedAt = time.UnixMilli(created).UTC()
	if finished > 0 {
		rec.FinishedAt = time.UnixMilli(finished).UTC()
	}
	return rec, true
}

// MemoryGitOps is the process-local ledger used by tests without STATE_DB.
type MemoryGitOps struct {
	mu    sync.Mutex
	byKey map[string]GitOpRecord
}

func gitOpKey(ownerID, workspaceID, key string) string {
	return ownerID + "\x00" + workspaceID + "\x00" + key
}

func (m *MemoryGitOps) AcquireGitOp(rec GitOpRecord) (GitOpAction, GitOpRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byKey == nil {
		m.byKey = map[string]GitOpRecord{}
	}
	k := gitOpKey(rec.OwnerID, rec.WorkspaceID, rec.IdempotencyKey)
	existing, ok := m.byKey[k]
	if !ok {
		if rec.CreatedAt.IsZero() {
			rec.CreatedAt = time.Now().UTC()
		}
		rec.Status = GitOpPending
		m.byKey[k] = rec
		return GitOpAcquired, rec
	}
	if existing.Operation != rec.Operation || existing.RequestFingerprint != rec.RequestFingerprint {
		return GitOpFingerprintConflict, existing
	}
	if existing.Status == GitOpSucceeded {
		return GitOpReplaySucceeded, existing
	}
	if existing.Status == GitOpPending {
		return GitOpInFlight, existing
	}
	return GitOpReconcileRequired, existing
}

func (m *MemoryGitOps) FinishGitOp(ownerID, workspaceID, key string, status GitOpStatus, resultJSON, errorJSON, localSHA string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byKey == nil {
		return false
	}
	k := gitOpKey(ownerID, workspaceID, key)
	rec, ok := m.byKey[k]
	if !ok {
		return false
	}
	rec.Status = status
	if resultJSON != "" {
		rec.ResultJSON = resultJSON
	}
	if errorJSON != "" {
		rec.ErrorJSON = errorJSON
	}
	if localSHA != "" {
		rec.LocalCommitSHA = localSHA
	}
	rec.FinishedAt = time.Now().UTC()
	m.byKey[k] = rec
	return true
}

// ReplayResult unmarshals a succeeded ledger payload into a ToolResult-shaped map.
func ReplayResult(raw string) (message string, data any, ok bool) {
	var payload struct {
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal([]byte(raw), &payload) != nil || payload.Message == "" {
		return "", nil, false
	}
	var dataVal any
	_ = json.Unmarshal(payload.Data, &dataVal)
	return payload.Message, dataVal, true
}
