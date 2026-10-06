package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxQueuedRecords   = 64
	maxPendingMsgBytes = 512 * 1024
	redactedMarker     = "[REDACTED]"
	defaultGatewayURL  = "http://model-gateway:3210/v1"
)

var allowedProxyOpsRuntime = map[string]struct{}{
	"files_list": {}, "files_read": {}, "files_write": {}, "files_apply_patch": {},
	"files_delete": {}, "files_move": {}, "files_mkdir": {}, "grep_search": {},
	"symbols_search": {}, "symbols_references": {},
}

// Runtime is the in-container JSONL agent. Prompt and lease travel only on
// stdin; they never appear in logs or terminal JSON beyond redaction.
type Runtime struct {
	in      io.Reader
	out     io.Writer
	gateway string
	client  *http.Client
	ctx     context.Context

	mu           sync.Mutex
	started      bool
	finalizing   bool
	sequence     int
	emitted      int
	outBytes     int
	start        StartRecord
	secrets      []string
	pending      []MessageRecord
	pendingN     int
	pendingTools map[string]chan ToolResultRecord
	finished     chan struct{}
	finishOnce   sync.Once
}

// ServeRuntime reads JSONL from stdin until a terminal record is written.
func ServeRuntime(ctx context.Context, in io.Reader, out io.Writer) error {
	return ServeRuntimeWith(ctx, in, out, strings.TrimSpace(os.Getenv("AGENT_MODEL_GATEWAY_URL")), nil)
}

// ServeRuntimeWith is the testable entry. Prompt/lease never log.
func ServeRuntimeWith(ctx context.Context, in io.Reader, out io.Writer, gateway string, client *http.Client) error {
	if ctx == nil {
		ctx = context.Background()
	}
	rt := &Runtime{
		in:           in,
		out:          out,
		gateway:      gateway,
		client:       client,
		ctx:          ctx,
		pendingTools: map[string]chan ToolResultRecord{},
		finished:     make(chan struct{}),
	}
	if rt.gateway == "" {
		rt.gateway = defaultGatewayURL
	}
	if rt.client == nil {
		rt.client = &http.Client{Timeout: 5 * time.Minute}
	}
	if err := validateGatewayURL(rt.gateway); err != nil {
		return rt.failClosed("FAILED", err.Error())
	}
	go func() {
		<-ctx.Done()
		rt.interrupt("runtime received termination signal")
	}()
	go func() { _ = rt.loop() }()
	<-rt.finished
	return nil
}

func (rt *Runtime) loop() error {
	br := bufio.NewReaderSize(rt.in, 64*1024)
	queued := 0
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if err == io.EOF && len(line) == 0 {
				rt.interrupt("protocol input closed before terminal state")
				return nil
			}
			if err == io.EOF {
				return rt.failClosed("FAILED", "unterminated protocol record")
			}
			rt.interrupt("protocol input failed")
			return nil
		}
		queued += len(line)
		if queued > MaxProtocolQueueBytes {
			return rt.failClosed("FAILED", "protocol receive queue exceeded its bound")
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(line) == 0 {
			continue
		}
		if len(line) > MaxProtocolRecordBytes {
			return rt.failClosed("FAILED", "protocol record exceeds byte limit")
		}
		if err := rt.receive(line); err != nil {
			return err
		}
		if rt.done() {
			return nil
		}
	}
}

func (rt *Runtime) done() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.finalizing
}

func (rt *Runtime) receive(line []byte) error {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &probe); err != nil || probe.Type == "" {
		return rt.failClosed("FAILED", "protocol record is invalid")
	}
	rt.mu.Lock()
	if rt.finalizing {
		rt.mu.Unlock()
		return rt.failClosed("FAILED", "protocol input received after terminal state")
	}
	if !rt.started {
		if probe.Type != "start" {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "first protocol record must be start")
		}
		var start StartRecord
		if err := json.Unmarshal(line, &start); err != nil {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "protocol record is invalid")
		}
		if err := validateStart(start); err != nil {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", err.Error())
		}
		rt.started = true
		rt.start = start
		if start.Gateway.Lease != "" {
			rt.secrets = append(rt.secrets, start.Gateway.Lease)
		}
		rt.mu.Unlock()
		go rt.run(start)
		return nil
	}
	if probe.Type == "start" {
		rt.mu.Unlock()
		return rt.failClosed("FAILED", "duplicate start record")
	}
	switch probe.Type {
	case "cancel":
		var rec CancelRecord
		_ = json.Unmarshal(line, &rec)
		reason := rec.Reason
		if reason == "" {
			reason = "agent cancelled"
		}
		err := rt.finishLocked("CANCELLED", reason)
		rt.mu.Unlock()
		return err
	case "message":
		var rec MessageRecord
		if err := json.Unmarshal(line, &rec); err != nil || rec.Text == "" {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "protocol record is invalid")
		}
		if rec.Behavior != "steer" && rec.Behavior != "followUp" {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "protocol record is invalid")
		}
		bytesN := len(rec.Text)
		if len(rt.pending) >= maxQueuedRecords || rt.pendingN+bytesN > maxPendingMsgBytes {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "pending message queue overflow")
		}
		rt.pending = append(rt.pending, rec)
		rt.pendingN += bytesN
		steering, followUp := pendingCounts(rt.pending)
		queue, _ := json.Marshal(map[string]any{"kind": "queue", "steering": steering, "followUp": followUp})
		_ = rt.emitLocked(OutputRecord{Type: "event", Sequence: rt.nextSeq(), Event: queue})
		rt.mu.Unlock()
		return nil
	case "tool_result":
		var rec ToolResultRecord
		if err := json.Unmarshal(line, &rec); err != nil || rec.RequestID == "" {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "protocol record is invalid")
		}
		if len(line) > rt.start.Limits.MaxToolResultBytes && rt.start.Limits.MaxToolResultBytes > 0 {
			rt.mu.Unlock()
			return rt.failClosed("LIMIT_EXCEEDED", "tool result exceeds job byte limit")
		}
		ch, ok := rt.pendingTools[rec.RequestID]
		if !ok {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "tool result references an unknown request")
		}
		delete(rt.pendingTools, rec.RequestID)
		rt.mu.Unlock()
		ch <- rec
		return nil
	case "tool_cancel":
		var rec CancelRecord
		_ = json.Unmarshal(line, &rec)
		ch, ok := rt.pendingTools[rec.RequestID]
		if !ok {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "tool cancellation references an unknown request")
		}
		delete(rt.pendingTools, rec.RequestID)
		reason := rec.Reason
		if reason == "" {
			reason = "tool request cancelled"
		}
		reason = rt.redact(reason, 1024)
		rt.mu.Unlock()
		ch <- ToolResultRecord{
			Type: "tool_result", RequestID: rec.RequestID, Final: true, IsError: true,
			Content: []ToolResultText{{Type: "text", Text: reason}},
		}
		return nil
	default:
		rt.mu.Unlock()
		return rt.failClosed("FAILED", "protocol record is invalid")
	}
}

func (rt *Runtime) run(start StartRecord) {
	deadline := time.Duration(start.Limits.DeadlineMs) * time.Millisecond
	if deadline < time.Second {
		deadline = time.Second
	}
	parent := rt.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	err := rt.session(ctx, start)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.finalizing {
		return
	}
	if err != nil {
		state := "FAILED"
		msg := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			state = "TIMED_OUT"
			msg = "agent deadline exceeded"
		} else if ctx.Err() != nil {
			state = "INTERRUPTED"
			msg = "runtime received termination signal"
		} else if isLimitExceeded(msg) {
			state = "LIMIT_EXCEEDED"
		}
		_ = rt.finishLocked(state, rt.redact(msg, 4096))
		return
	}
	_ = rt.finishLocked("SUCCEEDED", "")
}

type chatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []toolCall `json:"tool_calls,omitempty"`
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

func (rt *Runtime) session(ctx context.Context, start StartRecord) error {
	messages := []chatMessage{{Role: "user", Content: start.Prompt}}
	if err := rt.emitLifecycle("started"); err != nil {
		return err
	}
	for {
		rt.mu.Lock()
		done := rt.finalizing
		queued := append([]MessageRecord(nil), rt.pending...)
		rt.pending = nil
		rt.pendingN = 0
		rt.mu.Unlock()
		if done {
			return fmt.Errorf("runtime already terminal")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, rec := range queued {
			messages = append(messages, chatMessage{Role: "user", Content: rec.Text})
		}
		if err := rt.emitLifecycle("turn_started"); err != nil {
			return err
		}
		raw, err := rt.callGateway(ctx, start, messages)
		if err != nil {
			return err
		}
		assistant, err := parseAssistant(raw)
		if err != nil {
			return err
		}
		if err := rt.emitAssistant(start, assistant, raw); err != nil {
			return err
		}
		if err := rt.emitLifecycle("turn_ended"); err != nil {
			return err
		}
		if len(assistant.ToolCalls) == 0 {
			rt.mu.Lock()
			more := len(rt.pending) > 0
			rt.mu.Unlock()
			if more {
				messages = append(messages, assistant)
				continue
			}
			if err := rt.emitLifecycle("settled"); err != nil {
				return err
			}
			return nil
		}
		messages = append(messages, assistant)
		for _, call := range assistant.ToolCalls {
			result, err := rt.proxyTool(ctx, start, call)
			if err != nil {
				return err
			}
			messages = append(messages, chatMessage{
				Role:       "tool",
				ToolCallID: call.ID,
				Content:    toolResultText(result),
			})
		}
	}
}

func (rt *Runtime) emitLifecycle(phase string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.finalizing {
		return fmt.Errorf("runtime already terminal")
	}
	event, _ := json.Marshal(map[string]any{"kind": "lifecycle", "phase": phase})
	return rt.emitLocked(OutputRecord{Type: "event", Sequence: rt.nextSeq(), Event: event})
}

func pendingCounts(recs []MessageRecord) (steering, followUp int) {
	for _, rec := range recs {
		switch rec.Behavior {
		case "steer":
			steering++
		default:
			followUp++
		}
	}
	return
}

func (rt *Runtime) callGateway(ctx context.Context, start StartRecord, messages []chatMessage) ([]byte, error) {
	base, err := url.Parse(strings.TrimRight(rt.gateway, "/"))
	if err != nil {
		return nil, err
	}
	path := "/chat/completions"
	if start.Model.API == "openai-responses" {
		path = "/responses"
	}
	target := *base
	target.Path = strings.TrimRight(base.Path, "/") + path
	body, _ := json.Marshal(map[string]any{
		"model":    start.Model.ID,
		"messages": messages,
		"tools":    openaiTools(start.Tools),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+start.Gateway.Lease)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", start.AgentID)
	req.Header.Set("X-Model-Profile", start.Gateway.Profile)
	res, err := rt.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusRequestEntityTooLarge {
		return nil, fmt.Errorf("model budget exceeded (%d)", res.StatusCode)
	}
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("model provider request failed (%d)", res.StatusCode)
	}
	return raw, nil
}

func (rt *Runtime) emitAssistant(start StartRecord, assistant chatMessage, raw []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.finalizing {
		return fmt.Errorf("runtime already terminal")
	}
	if assistant.Content != "" {
		event, _ := json.Marshal(map[string]any{"kind": "text_delta", "text": rt.redact(assistant.Content, start.Limits.MaxEventBytes)})
		if err := rt.emitLocked(OutputRecord{Type: "event", Sequence: rt.nextSeq(), Event: event}); err != nil {
			return err
		}
	}
	usage := Usage{}
	if prov := usageFromProvider(raw, Profile{
		InputMicrosPerMillion:  int64(start.Model.Cost.Input * 1_000_000),
		OutputMicrosPerMillion: int64(start.Model.Cost.Output * 1_000_000),
	}); prov != nil {
		usage.Input = prov.InputTokens
		usage.Output = prov.OutputTokens
		usage.Total = prov.InputTokens + prov.OutputTokens
		usage.Cost = float64(prov.CostMicros) / 1_000_000
	}
	return rt.emitLocked(OutputRecord{Type: "usage", Sequence: rt.nextSeq(), Usage: &usage})
}

func (rt *Runtime) proxyTool(ctx context.Context, start StartRecord, call toolCall) (ToolResultRecord, error) {
	op := call.Function.Name
	if _, ok := allowedProxyOpsRuntime[op]; !ok {
		return ToolResultRecord{}, fmt.Errorf("proxy operation is not granted")
	}
	granted := false
	for _, name := range start.Tools {
		if name == op {
			granted = true
			break
		}
	}
	if !granted {
		return ToolResultRecord{}, fmt.Errorf("proxy operation is not granted")
	}
	var input json.RawMessage
	if strings.TrimSpace(call.Function.Arguments) == "" {
		input = json.RawMessage(`{}`)
	} else if json.Valid([]byte(call.Function.Arguments)) {
		input = json.RawMessage(call.Function.Arguments)
	} else {
		return ToolResultRecord{}, fmt.Errorf("tool arguments are invalid")
	}
	requestID := boundedRequestID(call.ID)
	wait := make(chan ToolResultRecord, 1)
	rt.mu.Lock()
	if rt.finalizing {
		rt.mu.Unlock()
		return ToolResultRecord{}, fmt.Errorf("runtime already terminal")
	}
	started, _ := json.Marshal(map[string]any{"kind": "tool", "phase": "started", "toolCallId": requestID, "name": op})
	if err := rt.emitLocked(OutputRecord{Type: "event", Sequence: rt.nextSeq(), Event: started}); err != nil {
		rt.mu.Unlock()
		return ToolResultRecord{}, err
	}
	rt.pendingTools[requestID] = wait
	if err := rt.emitLocked(OutputRecord{
		Type: "tool_request", RequestID: requestID, ToolCallID: requestID, Operation: op, Input: input,
	}); err != nil {
		delete(rt.pendingTools, requestID)
		rt.mu.Unlock()
		return ToolResultRecord{}, err
	}
	rt.mu.Unlock()
	select {
	case <-ctx.Done():
		rt.mu.Lock()
		delete(rt.pendingTools, requestID)
		rt.mu.Unlock()
		return ToolResultRecord{}, ctx.Err()
	case result := <-wait:
		rt.mu.Lock()
		if !rt.finalizing {
			ended, _ := json.Marshal(map[string]any{"kind": "tool", "phase": "ended", "toolCallId": requestID, "name": op, "isError": result.IsError})
			_ = rt.emitLocked(OutputRecord{Type: "event", Sequence: rt.nextSeq(), Event: ended})
		}
		rt.mu.Unlock()
		return result, nil
	}
}

func (rt *Runtime) cancelPendingLocked(reason string) {
	if reason == "" {
		reason = "agent session ended"
	}
	for id, ch := range rt.pendingTools {
		_ = rt.emitLocked(OutputRecord{Type: "tool_cancel", RequestID: id, Reason: rt.redact(reason, 1024)})
		select {
		case ch <- ToolResultRecord{
			Type: "tool_result", RequestID: id, Final: true, IsError: true,
			Content: []ToolResultText{{Type: "text", Text: rt.redact(reason, 1024)}},
		}:
		default:
		}
		delete(rt.pendingTools, id)
	}
}

func (rt *Runtime) interrupt(reason string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.finalizing {
		return
	}
	_ = rt.finishLocked("INTERRUPTED", reason)
}

func (rt *Runtime) failClosed(state, reason string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.failLocked(state, reason)
}

func (rt *Runtime) failLocked(state, reason string) error {
	_ = rt.finishLocked(state, reason)
	return nil
}

func (rt *Runtime) finishLocked(state, errMsg string) error {
	if rt.finalizing {
		return nil
	}
	rt.finalizing = true
	rt.cancelPendingLocked(errMsg)
	usage := Usage{}
	rec := OutputRecord{Type: "terminal", State: state, Usage: &usage}
	if errMsg != "" {
		rec.Error = rt.redact(errMsg, 4096)
	}
	err := rt.emitLocked(rec)
	rt.finishOnce.Do(func() { close(rt.finished) })
	return err
}

func (rt *Runtime) nextSeq() int {
	rt.sequence++
	return rt.sequence
}

func (rt *Runtime) emitLocked(rec OutputRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if rec.Type != "terminal" {
		rt.emitted++
		rt.outBytes += len(raw) + 1
		if rt.start.Limits.MaxEvents > 0 && rt.emitted > rt.start.Limits.MaxEvents {
			return rt.finishLocked("LIMIT_EXCEEDED", "agent output event limit exceeded")
		}
		if rt.start.Limits.MaxOutputBytes > 0 && rt.outBytes > rt.start.Limits.MaxOutputBytes {
			return rt.finishLocked("LIMIT_EXCEEDED", "agent output byte limit exceeded")
		}
	}
	_, err = rt.out.Write(append(raw, '\n'))
	return err
}

func (rt *Runtime) redact(value string, maxBytes int) string {
	text := value
	for _, secret := range rt.secrets {
		if len(secret) >= 4 {
			text = strings.ReplaceAll(text, secret, redactedMarker)
		}
	}
	text = secretLike.ReplaceAllStringFunc(text, func(m string) string {
		if strings.HasPrefix(strings.ToLower(m), "bearer ") {
			return "bearer " + redactedMarker
		}
		return redactedMarker
	})
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	if len(text) <= maxBytes {
		return text
	}
	if maxBytes <= 3 {
		return strings.Repeat(".", maxBytes)
	}
	return text[:maxBytes-3] + "…"
}

func validateStart(start StartRecord) error {
	if start.Type != "start" {
		return fmt.Errorf("first protocol record must be start")
	}
	if !ValidAgentID(start.AgentID) {
		return fmt.Errorf("agentId is invalid")
	}
	if strings.TrimSpace(start.Prompt) == "" || len(start.Prompt) > 128*1024 {
		return fmt.Errorf("prompt is invalid")
	}
	if start.Gateway.Profile == "" || start.Gateway.Lease == "" {
		return fmt.Errorf("gateway binding is required")
	}
	if len(start.Tools) < 1 || len(start.Tools) > len(allowedProxyOpsRuntime) {
		return fmt.Errorf("tools is invalid")
	}
	seen := map[string]struct{}{}
	for _, op := range start.Tools {
		if _, ok := allowedProxyOpsRuntime[op]; !ok {
			return fmt.Errorf("tools is invalid")
		}
		if _, ok := seen[op]; ok {
			return fmt.Errorf("duplicate proxy tool")
		}
		seen[op] = struct{}{}
	}
	if start.Model.API != "openai-completions" && start.Model.API != "openai-responses" {
		return fmt.Errorf("model api is invalid")
	}
	if start.Limits.DeadlineMs < 1_000 {
		return fmt.Errorf("limits are invalid")
	}
	return nil
}

func validateGatewayURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("model gateway URL must use HTTP or HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("model gateway URL cannot contain credentials, query parameters, or fragments")
	}
	if strings.Contains(raw, "sk-") || strings.Contains(strings.ToLower(raw), "api-key") {
		return fmt.Errorf("gateway URL must not carry provider credentials")
	}
	return nil
}

func parseAssistant(raw []byte) (chatMessage, error) {
	var envelope struct {
		Choices []struct {
			Message chatMessage `json:"message"`
		} `json:"choices"`
		OutputText string `json:"output_text"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return chatMessage{}, fmt.Errorf("model provider request failed")
	}
	if len(envelope.Choices) > 0 {
		msg := envelope.Choices[0].Message
		msg.Role = "assistant"
		return msg, nil
	}
	if envelope.OutputText != "" {
		return chatMessage{Role: "assistant", Content: envelope.OutputText}, nil
	}
	return chatMessage{Role: "assistant"}, nil
}

func openaiTools(names []string) []map[string]any {
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        name,
				"description": "Execute the bounded " + name + " operation in the validated workspace.",
				"parameters":  map[string]any{"type": "object", "additionalProperties": true},
			},
		})
	}
	return out
}

func toolResultText(rec ToolResultRecord) string {
	if len(rec.Content) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rec.Content))
	for _, item := range rec.Content {
		parts = append(parts, item.Text)
	}
	return strings.Join(parts, "\n")
}

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func boundedRequestID(value string) string {
	if requestIDRe.MatchString(value) {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	return "call_" + hex.EncodeToString(sum[:16])
}

func isLimitExceeded(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "429") || strings.Contains(lower, "413") ||
		strings.Contains(lower, "budget") || strings.Contains(lower, "limit")
}

var secretLike = regexp.MustCompile(`(?i)(bearer\s+)[^\s"']+|\bsk-[A-Za-z0-9_-]{8,}\b`)
