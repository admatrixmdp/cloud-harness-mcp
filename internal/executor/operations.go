package executor

import (
	"strconv"
	"sync"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	maxGenericOps     = 500
	genericRetainMs   = 600_000
	operationPageSize = 65_536
)

type genericOp struct {
	id         string
	root       string
	kind       string
	status     string
	createdAt  int64
	finishedAt int64
	deadlineMs int64
	result     any
	errCode    protocol.ErrorCode
	errMsg     string
	output     []byte
}

type genericHub struct {
	mu   sync.Mutex
	byID map[string]*genericOp
}

var generics = genericHub{byID: map[string]*genericOp{}}

func (h *genericHub) evictLocked(now int64) {
	for id, rec := range h.byID {
		if rec.status == "completed" || rec.status == "failed" || rec.status == "cancelled" {
			finished := rec.finishedAt
			if finished == 0 {
				finished = rec.createdAt
			}
			if now-finished >= genericRetainMs {
				delete(h.byID, id)
			}
		}
	}
}

func (h *genericHub) register(root, kind string, deadlineMs int64) (*genericOp, error) {
	now := time.Now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.evictLocked(now)
	if len(h.byID) >= maxGenericOps {
		return nil, errLimit("too many live or retained operation handles (maximum 500)")
	}
	rec := &genericOp{
		id:         protocol.NewOpaqueID(protocol.PrefixOperation),
		root:       root,
		kind:       kind,
		status:     "running",
		createdAt:  now,
		deadlineMs: deadlineMs,
	}
	h.byID[rec.id] = rec
	return rec, nil
}

type limitErr struct{ msg string }

func (e limitErr) Error() string { return e.msg }

func errLimit(msg string) error { return limitErr{msg: msg} }

func (h *genericHub) get(root, id string) *genericOp {
	now := time.Now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.evictLocked(now)
	rec := h.byID[id]
	if rec == nil || rec.root != root {
		return nil
	}
	return rec
}

func (h *genericHub) cancel(root, id string) *genericOp {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := h.byID[id]
	if rec == nil || rec.root != root {
		return nil
	}
	if rec.status == "running" || rec.status == "queued" {
		rec.status = "cancelled"
		rec.finishedAt = time.Now().UnixMilli()
	}
	return rec
}

func mapTaskStatus(status string) string {
	switch status {
	case "succeeded":
		return "completed"
	case "blocked":
		return "failed"
	case "failed", "cancelled", "queued", "running":
		if status == "queued" {
			return "running"
		}
		return status
	default:
		return "running"
	}
}

func isoMilli(ms int64) any {
	if ms <= 0 {
		return nil
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}

func (w Workspace) operationStatus(in pathInput) protocol.ToolResult {
	id := in.OperationID
	if !protocol.ValidOpaqueID(protocol.PrefixOperation, id) && !protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		return protocol.Fail(protocol.ErrorInvalidInput, "operationId is required", false)
	}
	if rec := generics.get(w.root(), id); rec != nil {
		return pageGeneric(rec, in.Cursor)
	}
	if protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		task := tasks.get(w.root(), id)
		if task == nil {
			return protocol.Fail(protocol.ErrorNotFound, "operation "+id+" not found", false)
		}
		return pageTaskAsOp(task, in.Cursor)
	}
	return protocol.Fail(protocol.ErrorNotFound, "operation "+id+" not found", false)
}

func (w Workspace) operationCancel(in pathInput) protocol.ToolResult {
	id := in.OperationID
	if !protocol.ValidOpaqueID(protocol.PrefixOperation, id) && !protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		return protocol.Fail(protocol.ErrorInvalidInput, "operationId is required", false)
	}
	if rec := generics.cancel(w.root(), id); rec != nil {
		return protocol.Success("Operation cancelled", map[string]any{"operationId": rec.id, "status": rec.status})
	}
	if protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		got := tasks.cancel(w.root(), id)
		if !got.OK {
			if got.Error != nil && got.Error.Code == protocol.ErrorNotFound {
				return protocol.Fail(protocol.ErrorNotFound, "operation "+id+" not found", false)
			}
			return got
		}
		data, _ := got.Data.(map[string]any)
		status, _ := data["status"].(string)
		return protocol.Success("Operation cancelled", map[string]any{"operationId": id, "status": mapTaskStatus(status)})
	}
	return protocol.Fail(protocol.ErrorNotFound, "operation "+id+" not found", false)
}

func (w Workspace) operationWait(in pathInput) protocol.ToolResult {
	id := in.OperationID
	if !protocol.ValidOpaqueID(protocol.PrefixOperation, id) && !protocol.ValidOpaqueID(protocol.PrefixTask, id) {
		return protocol.Fail(protocol.ErrorInvalidInput, "operationId is required", false)
	}
	timeout := in.TimeoutMs
	if timeout <= 0 {
		timeout = 60_000
	}
	if timeout > 300_000 {
		timeout = 300_000
	}
	deadline := time.Now().Add(time.Duration(timeout) * time.Millisecond)
	for {
		st := w.operationStatus(pathInput{OperationID: id})
		if !st.OK {
			if st.Error == nil || st.Error.Code == protocol.ErrorNotFound {
				return protocol.Fail(protocol.ErrorNotFound, "operation "+id+" not found", false)
			}
			if st.Error.Code == protocol.ErrorInvalidInput {
				return st
			}
		}
		data, _ := st.Data.(map[string]any)
		status, _ := data["status"].(string)
		if status == "completed" || status == "failed" || status == "cancelled" {
			ok := status == "completed"
			msg := "Operation " + status
			out := map[string]any{"operationId": id, "status": status, "result": data["result"], "finishedAt": data["finishedAt"]}
			if ok {
				return protocol.Success(msg, out)
			}
			fail := protocol.Fail(protocol.ErrorCancelled, msg, false)
			if status == "failed" {
				fail = protocol.Fail(protocol.ErrorInternal, msg, false)
			}
			fail.Data = out
			fail.Message = msg
			return fail
		}
		if !time.Now().Before(deadline) {
			fail := protocol.Fail(protocol.ErrorTimeout, "Operation did not reach terminal state within timeout", true)
			fail.Message = "Operation wait timed out"
			if fail.Error != nil {
				ms := 2000
				fail.Error.RetryAfterMs = &ms
				fail.Error.Deadline = deadline.UTC().Format(time.RFC3339Nano)
			}
			return fail
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func pageGeneric(rec *genericOp, cursor string) protocol.ToolResult {
	offset := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil || n < 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid operation output cursor", false)
		}
		offset = n
	}
	total := len(rec.output)
	if offset > total {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid operation output cursor", false)
	}
	end := offset + operationPageSize
	if end > total {
		end = total
	}
	data := map[string]any{
		"operationId": rec.id,
		"status":      rec.status,
		"kind":        rec.kind,
		"createdAt":   isoMilli(rec.createdAt),
		"deadline":    isoMilli(rec.deadlineMs),
		"finishedAt":  isoMilli(rec.finishedAt),
		"result":      rec.result,
		"output":      string(rec.output[offset:end]),
	}
	ok := rec.status != "failed" && rec.status != "cancelled"
	var got protocol.ToolResult
	if ok {
		got = protocol.Success("Operation "+rec.status, data)
	} else {
		got = protocol.Fail(protocol.ErrorCancelled, "Operation "+rec.status, false)
		got.Data = data
		got.Message = "Operation " + rec.status
	}
	if end < total {
		got.Cursor = strconv.Itoa(end)
		got.Truncated = true
	}
	return got
}

func pageTaskAsOp(rec *taskRecord, cursor string) protocol.ToolResult {
	page, err := rec.viewSince(cursor)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid operation output cursor", false)
	}
	view := rec.view()
	status := mapTaskStatus(view["status"].(string))
	data := map[string]any{
		"operationId": rec.id,
		"status":      status,
		"kind":        "task",
		"createdAt":   isoMilli(rec.createdAt),
		"result":      nil,
		"output":      page.data["output"],
	}
	ok := status != "failed" && status != "cancelled"
	var got protocol.ToolResult
	if ok {
		got = protocol.Success("Operation "+status, data)
	} else {
		got = protocol.Fail(protocol.ErrorCancelled, "Operation "+status, false)
		got.Data = data
		got.Message = "Operation " + status
	}
	got.Cursor = page.cursor
	got.Truncated = page.truncated
	return got
}
