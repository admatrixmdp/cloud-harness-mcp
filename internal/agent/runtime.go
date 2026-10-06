package agent

import (
	"bufio"
	"bytes"
	"context"
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

	mu         sync.Mutex
	started    bool
	finalizing bool
	sequence   int
	emitted    int
	outBytes   int
	start      StartRecord
	secrets    []string
	pending    []MessageRecord
	pendingN   int
	finished   chan struct{}
	finishOnce sync.Once
}

// ServeRuntime reads JSONL from stdin until a terminal record is written.
func ServeRuntime(ctx context.Context, in io.Reader, out io.Writer) error {
	return ServeRuntimeWith(ctx, in, out, strings.TrimSpace(os.Getenv("AGENT_MODEL_GATEWAY_URL")), nil)
}

// ServeRuntimeWith is the testable entry. Prompt/lease never log.
func ServeRuntimeWith(ctx context.Context, in io.Reader, out io.Writer, gateway string, client *http.Client) error {
	rt := &Runtime{
		in:       in,
		out:      out,
		gateway:  gateway,
		client:   client,
		finished: make(chan struct{}),
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
		bytesN := len(rec.Text)
		if len(rt.pending) >= maxQueuedRecords || rt.pendingN+bytesN > maxPendingMsgBytes {
			rt.mu.Unlock()
			return rt.failClosed("FAILED", "pending message queue overflow")
		}
		rt.pending = append(rt.pending, rec)
		rt.pendingN += bytesN
		rt.mu.Unlock()
		return nil
	case "tool_result", "tool_cancel":
		// Overlay runtime currently completes without issuing tool_request;
		// extra results after start are ignored so a TS runner can still fence.
		rt.mu.Unlock()
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
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	done := make(chan string, 1)
	go func() {
		err := rt.callGateway(start)
		if err != nil {
			done <- err.Error()
			return
		}
		done <- ""
	}()
	select {
	case <-timer.C:
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if rt.finalizing {
			return
		}
		_ = rt.finishLocked("TIMED_OUT", "agent deadline exceeded")
	case msg := <-done:
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if rt.finalizing {
			return
		}
		if msg != "" {
			state := "FAILED"
			if isLimitExceeded(msg) {
				state = "LIMIT_EXCEEDED"
			}
			_ = rt.finishLocked(state, rt.redact(msg, 4096))
			return
		}
		_ = rt.finishLocked("SUCCEEDED", "")
	}
}

func (rt *Runtime) callGateway(start StartRecord) error {
	base, err := url.Parse(strings.TrimRight(rt.gateway, "/"))
	if err != nil {
		return err
	}
	path := "/chat/completions"
	if start.Model.API == "openai-responses" {
		path = "/responses"
	}
	target := *base
	target.Path = strings.TrimRight(base.Path, "/") + path
	body, _ := json.Marshal(map[string]any{
		"model": start.Model.ID,
		"messages": []map[string]string{
			{"role": "user", "content": start.Prompt},
		},
	})
	req, err := http.NewRequest(http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+start.Gateway.Lease)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", start.AgentID)
	req.Header.Set("X-Model-Profile", start.Gateway.Profile)
	res, err := rt.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusRequestEntityTooLarge {
		return fmt.Errorf("model budget exceeded (%d)", res.StatusCode)
	}
	if res.StatusCode >= 400 {
		return fmt.Errorf("model provider request failed (%d)", res.StatusCode)
	}
	text := assistantText(raw)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.finalizing {
		return nil
	}
	event, _ := json.Marshal(map[string]any{"kind": "text_delta", "text": rt.redact(text, start.Limits.MaxEventBytes)})
	if err := rt.emitLocked(OutputRecord{Type: "event", Sequence: rt.nextSeq(), Event: event}); err != nil {
		return err
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

func assistantText(raw []byte) string {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	if choices, ok := obj["choices"].([]any); ok && len(choices) > 0 {
		if c, ok := choices[0].(map[string]any); ok {
			if msg, ok := c["message"].(map[string]any); ok {
				if t, ok := msg["content"].(string); ok {
					return t
				}
			}
			if t, ok := c["text"].(string); ok {
				return t
			}
		}
	}
	if t, ok := obj["output_text"].(string); ok {
		return t
	}
	return ""
}

func isLimitExceeded(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "429") || strings.Contains(lower, "413") ||
		strings.Contains(lower, "budget") || strings.Contains(lower, "limit")
}

var secretLike = regexp.MustCompile(`(?i)(bearer\s+)[^\s"']+|\bsk-[A-Za-z0-9_-]{8,}\b`)
