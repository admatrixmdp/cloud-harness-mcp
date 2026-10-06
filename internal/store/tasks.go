package store

import (
	"database/sql"
	"strings"
	"sync"
	"time"
)

// DurableTask is one durable_tasks row. Status is stored uppercase (TS schema);
// MCP envelopes keep the executor's lowercase view.
type DurableTask struct {
	ID                 string
	WorkspaceID        string
	OwnerID            string
	Name               string
	Command            string
	Cwd                string
	Status             string
	IdempotencyKey     string
	RequestFingerprint string
	BootID             string
	ExitCode           *int
	ErrorCode          string
	ErrorMessage       string
	TimeoutMs          int
	MaxBytes           int
	LogPath            string
	OutputBytes        int
	OutputArtifactID   string
	CreatedAt          int64
	StartedAt          int64
	FinishedAt         int64
	Generation         int
	DependsOn          []string
}

// TaskStore is the durable background-task ledger.
type TaskStore interface {
	PutTask(rec DurableTask) error
	GetTask(ownerID, workspaceID, id string) (DurableTask, bool)
	GetTaskByKey(ownerID, workspaceID, key string) (DurableTask, bool)
	ListTasks(ownerID, workspaceID string) []DurableTask
	UpdateTask(rec DurableTask) bool
	ReconcileStaleTasks(bootID string, now int64) int
}

const taskDDL = `
CREATE TABLE IF NOT EXISTS durable_tasks (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  name TEXT,
  command TEXT NOT NULL,
  cwd TEXT NOT NULL DEFAULT '.',
  status TEXT NOT NULL CHECK(status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'BLOCKED')),
  idempotency_key TEXT,
  request_fingerprint TEXT,
  boot_id TEXT NOT NULL,
  exit_code INTEGER,
  error_code TEXT,
  error_message TEXT,
  timeout_ms INTEGER NOT NULL DEFAULT 300000,
  max_bytes INTEGER NOT NULL DEFAULT 67108864,
  log_path TEXT NOT NULL,
  output_bytes INTEGER NOT NULL DEFAULT 0,
  output_artifact_id TEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  generation INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS durable_tasks_owner_ws_key ON durable_tasks(owner_id, workspace_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS durable_tasks_workspace_created ON durable_tasks(owner_id, workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS durable_tasks_boot_status ON durable_tasks(boot_id, status);
CREATE TABLE IF NOT EXISTS task_dependencies (
  task_id TEXT NOT NULL,
  depends_on_task_id TEXT NOT NULL,
  PRIMARY KEY(task_id, depends_on_task_id)
);
`

func ensureTaskSchema(db *sql.DB) error {
	_, err := db.Exec(taskDDL)
	return err
}

func (s *SQLite) PutTask(rec DurableTask) error {
	if err := ensureTaskSchema(s.db); err != nil {
		return err
	}
	if rec.Generation == 0 {
		rec.Generation = 1
	}
	if rec.TimeoutMs == 0 {
		rec.TimeoutMs = 300_000
	}
	if rec.MaxBytes == 0 {
		rec.MaxBytes = 67_108_864
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO durable_tasks
		(id, workspace_id, owner_id, name, command, cwd, status, idempotency_key, request_fingerprint, boot_id,
		 exit_code, error_code, error_message, timeout_ms, max_bytes, log_path, output_bytes, output_artifact_id,
		 created_at, started_at, finished_at, generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.WorkspaceID, rec.OwnerID, nullString(rec.Name), rec.Command, rec.Cwd, rec.Status,
		nullString(rec.IdempotencyKey), nullString(rec.RequestFingerprint), rec.BootID,
		nullIntPtr(rec.ExitCode), nullString(rec.ErrorCode), nullString(rec.ErrorMessage),
		rec.TimeoutMs, rec.MaxBytes, rec.LogPath, rec.OutputBytes, nullString(rec.OutputArtifactID),
		rec.CreatedAt, nullInt(rec.StartedAt), nullInt(rec.FinishedAt), rec.Generation); err != nil {
		return err
	}
	for _, dep := range rec.DependsOn {
		if _, err := tx.Exec(`INSERT INTO task_dependencies (task_id, depends_on_task_id) VALUES (?, ?)`, rec.ID, dep); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) GetTask(ownerID, workspaceID, id string) (DurableTask, bool) {
	if err := ensureTaskSchema(s.db); err != nil {
		return DurableTask{}, false
	}
	return s.scanTask(`SELECT id, workspace_id, owner_id, IFNULL(name,''), command, cwd, status, IFNULL(idempotency_key,''),
		IFNULL(request_fingerprint,''), boot_id, exit_code, IFNULL(error_code,''), IFNULL(error_message,''),
		timeout_ms, max_bytes, log_path, output_bytes, IFNULL(output_artifact_id,''), created_at,
		IFNULL(started_at,0), IFNULL(finished_at,0), generation
		FROM durable_tasks WHERE owner_id = ? AND workspace_id = ? AND id = ?`, ownerID, workspaceID, id)
}

func (s *SQLite) GetTaskByKey(ownerID, workspaceID, key string) (DurableTask, bool) {
	if err := ensureTaskSchema(s.db); err != nil {
		return DurableTask{}, false
	}
	return s.scanTask(`SELECT id, workspace_id, owner_id, IFNULL(name,''), command, cwd, status, IFNULL(idempotency_key,''),
		IFNULL(request_fingerprint,''), boot_id, exit_code, IFNULL(error_code,''), IFNULL(error_message,''),
		timeout_ms, max_bytes, log_path, output_bytes, IFNULL(output_artifact_id,''), created_at,
		IFNULL(started_at,0), IFNULL(finished_at,0), generation
		FROM durable_tasks WHERE owner_id = ? AND workspace_id = ? AND idempotency_key = ?`, ownerID, workspaceID, key)
}

func (s *SQLite) ListTasks(ownerID, workspaceID string) []DurableTask {
	if err := ensureTaskSchema(s.db); err != nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, workspace_id, owner_id, IFNULL(name,''), command, cwd, status, IFNULL(idempotency_key,''),
		IFNULL(request_fingerprint,''), boot_id, exit_code, IFNULL(error_code,''), IFNULL(error_message,''),
		timeout_ms, max_bytes, log_path, output_bytes, IFNULL(output_artifact_id,''), created_at,
		IFNULL(started_at,0), IFNULL(finished_at,0), generation
		FROM durable_tasks WHERE owner_id = ? AND workspace_id = ? ORDER BY created_at ASC`, ownerID, workspaceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []DurableTask
	for rows.Next() {
		rec, err := scanTaskRow(rows)
		if err != nil {
			return out
		}
		rec.DependsOn = s.depsFor(rec.ID)
		out = append(out, rec)
	}
	return out
}

func (s *SQLite) UpdateTask(rec DurableTask) bool {
	if err := ensureTaskSchema(s.db); err != nil {
		return false
	}
	res, err := s.db.Exec(`UPDATE durable_tasks SET status = ?, exit_code = ?, error_code = ?, error_message = ?,
		started_at = ?, finished_at = ?, output_bytes = ?, output_artifact_id = ?, generation = generation + 1
		WHERE id = ? AND generation = ?`,
		rec.Status, nullIntPtr(rec.ExitCode), nullString(rec.ErrorCode), nullString(rec.ErrorMessage),
		nullInt(rec.StartedAt), nullInt(rec.FinishedAt), rec.OutputBytes, nullString(rec.OutputArtifactID),
		rec.ID, rec.Generation)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (s *SQLite) ReconcileStaleTasks(bootID string, now int64) int {
	if err := ensureTaskSchema(s.db); err != nil {
		return 0
	}
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	res, err := s.db.Exec(`UPDATE durable_tasks
		SET status = 'FAILED', error_code = 'RUNNER_RESTARTED',
		    error_message = 'Task execution interrupted by runner restart',
		    finished_at = ?, generation = generation + 1
		WHERE status IN ('QUEUED', 'RUNNING') AND boot_id != ?`, now, bootID)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

func (s *SQLite) scanTask(q string, args ...any) (DurableTask, bool) {
	rec, err := scanTaskRow(s.db.QueryRow(q, args...))
	if err != nil {
		return DurableTask{}, false
	}
	rec.DependsOn = s.depsFor(rec.ID)
	return rec, true
}

func (s *SQLite) depsFor(id string) []string {
	rows, err := s.db.Query(`SELECT depends_on_task_id FROM task_dependencies WHERE task_id = ?`, id)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var dep string
		if err := rows.Scan(&dep); err != nil {
			return out
		}
		out = append(out, dep)
	}
	return out
}

type taskScanner interface {
	Scan(dest ...any) error
}

func scanTaskRow(row taskScanner) (DurableTask, error) {
	var rec DurableTask
	var exit sql.NullInt64
	if err := row.Scan(&rec.ID, &rec.WorkspaceID, &rec.OwnerID, &rec.Name, &rec.Command, &rec.Cwd, &rec.Status,
		&rec.IdempotencyKey, &rec.RequestFingerprint, &rec.BootID, &exit, &rec.ErrorCode, &rec.ErrorMessage,
		&rec.TimeoutMs, &rec.MaxBytes, &rec.LogPath, &rec.OutputBytes, &rec.OutputArtifactID,
		&rec.CreatedAt, &rec.StartedAt, &rec.FinishedAt, &rec.Generation); err != nil {
		return DurableTask{}, err
	}
	if exit.Valid {
		v := int(exit.Int64)
		rec.ExitCode = &v
	}
	return rec, nil
}

func nullIntPtr(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// MemoryTasks is the process-local ledger used by tests without STATE_DB.
type MemoryTasks struct {
	mu    sync.Mutex
	byID  map[string]DurableTask
	byKey map[string]string
}

func taskMapKey(ownerID, workspaceID, key string) string {
	return ownerID + "\x00" + workspaceID + "\x00" + key
}

func (m *MemoryTasks) PutTask(rec DurableTask) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byID == nil {
		m.byID = map[string]DurableTask{}
		m.byKey = map[string]string{}
	}
	if rec.Generation == 0 {
		rec.Generation = 1
	}
	m.byID[rec.ID] = rec
	if rec.IdempotencyKey != "" {
		m.byKey[taskMapKey(rec.OwnerID, rec.WorkspaceID, rec.IdempotencyKey)] = rec.ID
	}
	return nil
}

func (m *MemoryTasks) GetTask(ownerID, workspaceID, id string) (DurableTask, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok || rec.OwnerID != ownerID || rec.WorkspaceID != workspaceID {
		return DurableTask{}, false
	}
	return rec, true
}

func (m *MemoryTasks) GetTaskByKey(ownerID, workspaceID, key string) (DurableTask, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byKey[taskMapKey(ownerID, workspaceID, key)]
	if !ok {
		return DurableTask{}, false
	}
	rec, ok := m.byID[id]
	return rec, ok
}

func (m *MemoryTasks) ListTasks(ownerID, workspaceID string) []DurableTask {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DurableTask
	for _, rec := range m.byID {
		if rec.OwnerID == ownerID && rec.WorkspaceID == workspaceID {
			out = append(out, rec)
		}
	}
	return out
}

func (m *MemoryTasks) UpdateTask(rec DurableTask) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.byID[rec.ID]
	if !ok || cur.Generation != rec.Generation {
		return false
	}
	rec.Generation++
	m.byID[rec.ID] = rec
	return true
}

func (m *MemoryTasks) ReconcileStaleTasks(bootID string, now int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, rec := range m.byID {
		if rec.BootID == bootID {
			continue
		}
		if rec.Status != "QUEUED" && rec.Status != "RUNNING" {
			continue
		}
		rec.Status = "FAILED"
		rec.ErrorCode = "RUNNER_RESTARTED"
		rec.ErrorMessage = "Task execution interrupted by runner restart"
		rec.FinishedAt = now
		rec.Generation++
		m.byID[id] = rec
		n++
	}
	return n
}

// DurableStatus maps the MCP lowercase task status onto the SQLite CHECK value.
func DurableStatus(live string) string {
	switch strings.ToLower(live) {
	case "queued":
		return "QUEUED"
	case "running":
		return "RUNNING"
	case "succeeded":
		return "SUCCEEDED"
	case "failed":
		return "FAILED"
	case "cancelled":
		return "CANCELLED"
	case "blocked":
		return "BLOCKED"
	default:
		return strings.ToUpper(live)
	}
}

// LiveStatus maps a SQLite CHECK value onto the MCP lowercase task status.
func LiveStatus(stored string) string {
	switch stored {
	case "QUEUED":
		return "queued"
	case "RUNNING":
		return "running"
	case "SUCCEEDED":
		return "succeeded"
	case "FAILED":
		return "failed"
	case "CANCELLED":
		return "cancelled"
	case "BLOCKED":
		return "blocked"
	default:
		return strings.ToLower(stored)
	}
}
