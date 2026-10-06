package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServeRuntimeCompletesWithoutLeakingLease(t *testing.T) {
	var seenAuth, seenAgent, seenProfile string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenAgent = r.Header.Get("X-Agent-ID")
		seenProfile = r.Header.Get("X-Model-Profile")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello lease_secret_token_value_xxxxxxxxxxxx"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
	}))
	t.Cleanup(upstream.Close)

	agentID := "agent_" + strings.Repeat("r", 24)
	start := StartRecord{
		Type: "start", RequestID: "req-1", AgentID: agentID,
		Prompt: "secret prompt", Tools: []string{"files_read"},
		Gateway: StartGateway{Profile: "coding-fast", Lease: "lease_secret_token_value_xxxxxxxxxxxx"},
		Model:   StartModel{ID: "gpt", Name: "gpt", API: "openai-completions", ContextWindow: 8_000, MaxTokens: 1_024},
		Limits:  StartLimits{DeadlineMs: 5_000, MaxEvents: 100, MaxOutputBytes: 65_536, MaxEventBytes: 4_096, MaxToolResultBytes: 4_096},
	}
	raw, _ := json.Marshal(start)
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(append(raw, '\n'))
	}()
	t.Cleanup(func() { _ = pw.Close() })
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := ServeRuntimeWith(ctx, pr, &out, upstream.URL+"/v1", upstream.Client()); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "lease_secret_token_value_xxxxxxxxxxxx") || strings.Contains(got, "secret prompt") {
		t.Fatalf("secret leaked into stdout: %s", got)
	}
	if !strings.Contains(got, `"type":"terminal"`) || !strings.Contains(got, `"SUCCEEDED"`) {
		t.Fatalf("missing terminal %s", got)
	}
	if !strings.Contains(got, redactedMarker) {
		t.Fatalf("assistant text must redact lease: %s", got)
	}
	if seenAuth != "Bearer lease_secret_token_value_xxxxxxxxxxxx" {
		t.Fatalf("lease must ride Authorization, got %q", seenAuth)
	}
	if seenAgent != agentID || seenProfile != "coding-fast" {
		t.Fatalf("headers %q %q", seenAgent, seenProfile)
	}
}

func TestServeRuntimeCancelBeforeStartFailsClosed(t *testing.T) {
	in := bytes.NewReader([]byte(`{"type":"cancel","requestId":"x"}` + "\n"))
	var out bytes.Buffer
	if err := ServeRuntimeWith(context.Background(), in, &out, "http://127.0.0.1:9/v1", http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"FAILED"`) || !strings.Contains(out.String(), "first protocol record must be start") {
		t.Fatalf("%s", out.String())
	}
}

func TestServeRuntimeDeadlineTimesOut(t *testing.T) {
	block := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	t.Cleanup(func() { close(block); upstream.Close() })
	start := StartRecord{
		Type: "start", RequestID: "req-1", AgentID: "agent_" + strings.Repeat("t", 24),
		Prompt: "go", Tools: []string{"files_list"},
		Gateway: StartGateway{Profile: "coding-fast", Lease: "lease_secret_token_value_xxxxxxxxxxxx"},
		Model:   StartModel{ID: "gpt", Name: "gpt", API: "openai-completions", ContextWindow: 100, MaxTokens: 10},
		Limits:  StartLimits{DeadlineMs: 1_000, MaxEvents: 10, MaxOutputBytes: 4096, MaxEventBytes: 256, MaxToolResultBytes: 256},
	}
	raw, _ := json.Marshal(start)
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(append(raw, '\n'))
	}()
	t.Cleanup(func() { _ = pw.Close() })
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := ServeRuntimeWith(ctx, pr, &out, upstream.URL+"/v1", upstream.Client()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"TIMED_OUT"`) {
		t.Fatalf("expected deadline terminal, got %s", out.String())
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *lockedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *lockedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func waitFor(t *testing.T, w *lockedBuffer, needle string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		got := w.String()
		if strings.Contains(got, needle) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s, got %s", needle, w.String())
	return ""
}

func TestServeRuntimeProxiesGrantedToolCall(t *testing.T) {
	var calls atomicInt
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.add()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_files","type":"function","function":{"name":"files_read","arguments":"{\"path\":\"README.md\"}"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"done lease_secret_token_value_xxxxxxxxxxxx"}}],"usage":{"prompt_tokens":2,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)

	start := StartRecord{
		Type: "start", RequestID: "req-1", AgentID: "agent_" + strings.Repeat("p", 24),
		Prompt: "read it", Tools: []string{"files_read"},
		Gateway: StartGateway{Profile: "coding-fast", Lease: "lease_secret_token_value_xxxxxxxxxxxx"},
		Model:   StartModel{ID: "gpt", Name: "gpt", API: "openai-completions", ContextWindow: 8_000, MaxTokens: 1_024},
		Limits:  StartLimits{DeadlineMs: 5_000, MaxEvents: 100, MaxOutputBytes: 65_536, MaxEventBytes: 4_096, MaxToolResultBytes: 4_096},
	}
	raw, _ := json.Marshal(start)
	pr, pw := io.Pipe()
	var out lockedBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeRuntimeWith(ctx, pr, &out, upstream.URL+"/v1", upstream.Client())
	}()
	if _, err := pw.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	snapshot := waitFor(t, &out, `"type":"tool_request"`, 2*time.Second)
	if !strings.Contains(snapshot, `"operation":"files_read"`) || !strings.Contains(snapshot, `"requestId":"call_files"`) {
		t.Fatalf("missing tool_request %s", snapshot)
	}
	if strings.Contains(snapshot, "lease_secret_token_value_xxxxxxxxxxxx") {
		t.Fatalf("lease leaked before result: %s", snapshot)
	}
	if _, err := pw.Write([]byte(`{"type":"tool_result","requestId":"call_files","final":true,"isError":false,"content":[{"type":"text","text":"ok"}]}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not settle after tool_result")
	}
	got := out.String()
	if !strings.Contains(got, `"SUCCEEDED"`) {
		t.Fatalf("missing terminal %s", got)
	}
	if strings.Contains(got, "lease_secret_token_value_xxxxxxxxxxxx") {
		t.Fatalf("lease leaked: %s", got)
	}
	if calls.value() != 2 {
		t.Fatalf("gateway calls = %d", calls.value())
	}
}

func TestServeRuntimeUnknownToolResultFailsClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_files","type":"function","function":{"name":"files_read","arguments":"{}"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)
	start := StartRecord{
		Type: "start", RequestID: "req-1", AgentID: "agent_" + strings.Repeat("u", 24),
		Prompt: "read it", Tools: []string{"files_read"},
		Gateway: StartGateway{Profile: "coding-fast", Lease: "lease_secret_token_value_xxxxxxxxxxxx"},
		Model:   StartModel{ID: "gpt", Name: "gpt", API: "openai-completions", ContextWindow: 100, MaxTokens: 10},
		Limits:  StartLimits{DeadlineMs: 5_000, MaxEvents: 20, MaxOutputBytes: 8192, MaxEventBytes: 1024, MaxToolResultBytes: 1024},
	}
	raw, _ := json.Marshal(start)
	pr, pw := io.Pipe()
	var out lockedBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeRuntimeWith(ctx, pr, &out, upstream.URL+"/v1", upstream.Client())
	}()
	_, _ = pw.Write(append(raw, '\n'))
	waitFor(t, &out, `"type":"tool_request"`, 2*time.Second)
	_, _ = pw.Write([]byte(`{"type":"tool_result","requestId":"call_other","final":true,"isError":false,"content":[{"type":"text","text":"nope"}]}` + "\n"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not fail closed")
	}
	got := out.String()
	if !strings.Contains(got, `"FAILED"`) || !strings.Contains(got, "unknown request") {
		t.Fatalf("%s", got)
	}
}

func TestServeRuntimeRejectsUngrantedToolName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_write","type":"function","function":{"name":"files_write","arguments":"{}"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)
	start := StartRecord{
		Type: "start", RequestID: "req-1", AgentID: "agent_" + strings.Repeat("g", 24),
		Prompt: "write", Tools: []string{"files_read"},
		Gateway: StartGateway{Profile: "coding-fast", Lease: "lease_secret_token_value_xxxxxxxxxxxx"},
		Model:   StartModel{ID: "gpt", Name: "gpt", API: "openai-completions", ContextWindow: 100, MaxTokens: 10},
		Limits:  StartLimits{DeadlineMs: 5_000, MaxEvents: 20, MaxOutputBytes: 8192, MaxEventBytes: 1024, MaxToolResultBytes: 1024},
	}
	raw, _ := json.Marshal(start)
	pr, pw := io.Pipe()
	var out lockedBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _, _ = pw.Write(append(raw, '\n')) }()
	if err := ServeRuntimeWith(ctx, pr, &out, upstream.URL+"/v1", upstream.Client()); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, `"type":"tool_request"`) {
		t.Fatalf("ungranted tool must not emit tool_request: %s", got)
	}
	if !strings.Contains(got, `"FAILED"`) || !strings.Contains(got, "not granted") {
		t.Fatalf("%s", got)
	}
}

func TestServeRuntimeFollowUpReachesGateway(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		n := len(bodies)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_files","type":"function","function":{"name":"files_read","arguments":"{}"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"followed up"}}],"usage":{"prompt_tokens":2,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)

	start := StartRecord{
		Type: "start", RequestID: "req-1", AgentID: "agent_" + strings.Repeat("m", 24),
		Prompt: "first", Tools: []string{"files_read"},
		Gateway: StartGateway{Profile: "coding-fast", Lease: "lease_secret_token_value_xxxxxxxxxxxx"},
		Model:   StartModel{ID: "gpt", Name: "gpt", API: "openai-completions", ContextWindow: 8_000, MaxTokens: 1_024},
		Limits:  StartLimits{DeadlineMs: 5_000, MaxEvents: 100, MaxOutputBytes: 65_536, MaxEventBytes: 4_096, MaxToolResultBytes: 4_096},
	}
	raw, _ := json.Marshal(start)
	pr, pw := io.Pipe()
	var out lockedBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeRuntimeWith(ctx, pr, &out, upstream.URL+"/v1", upstream.Client())
	}()
	_, _ = pw.Write(append(raw, '\n'))
	waitFor(t, &out, `"type":"tool_request"`, 2*time.Second)
	_, _ = pw.Write([]byte(`{"type":"message","requestId":"m1","behavior":"followUp","text":"keep going"}` + "\n"))
	waitFor(t, &out, `"kind":"queue"`, 2*time.Second)
	_, _ = pw.Write([]byte(`{"type":"tool_result","requestId":"call_files","final":true,"isError":false,"content":[{"type":"text","text":"ok"}]}` + "\n"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not settle after follow-up")
	}
	got := out.String()
	if !strings.Contains(got, `"SUCCEEDED"`) || !strings.Contains(got, `"followUp":1`) {
		t.Fatalf("%s", got)
	}
	if strings.Contains(got, "keep going") {
		t.Fatalf("follow-up text leaked into stdout: %s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) < 2 {
		t.Fatalf("expected follow-up gateway call, got %d", len(bodies))
	}
	if !strings.Contains(bodies[len(bodies)-1], "keep going") {
		t.Fatalf("follow-up missing from second request: %s", bodies[len(bodies)-1])
	}
}

func TestServeRuntimeRejectsUnknownMessageBehavior(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_files","type":"function","function":{"name":"files_read","arguments":"{}"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	t.Cleanup(upstream.Close)
	start := StartRecord{
		Type: "start", RequestID: "req-1", AgentID: "agent_" + strings.Repeat("b", 24),
		Prompt: "first", Tools: []string{"files_read"},
		Gateway: StartGateway{Profile: "coding-fast", Lease: "lease_secret_token_value_xxxxxxxxxxxx"},
		Model:   StartModel{ID: "gpt", Name: "gpt", API: "openai-completions", ContextWindow: 100, MaxTokens: 10},
		Limits:  StartLimits{DeadlineMs: 5_000, MaxEvents: 20, MaxOutputBytes: 8192, MaxEventBytes: 1024, MaxToolResultBytes: 1024},
	}
	raw, _ := json.Marshal(start)
	pr, pw := io.Pipe()
	var out lockedBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeRuntimeWith(ctx, pr, &out, upstream.URL+"/v1", upstream.Client())
	}()
	_, _ = pw.Write(append(raw, '\n'))
	waitFor(t, &out, `"type":"tool_request"`, 2*time.Second)
	_, _ = pw.Write([]byte(`{"type":"message","requestId":"m1","behavior":"shout","text":"nope"}` + "\n"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not fail closed")
	}
	if !strings.Contains(out.String(), `"FAILED"`) {
		t.Fatalf("%s", out.String())
	}
}

type atomicInt struct{ v atomic.Int32 }

func (a *atomicInt) add() int { return int(a.v.Add(1)) }

func (a *atomicInt) value() int { return int(a.v.Load()) }

func TestParseAssistantSSEToolCall(t *testing.T) {
	raw := []byte("data: " + `{"choices":[{"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_fake_write","type":"function","function":{"name":"files_write","arguments":"{\"path\":\"pi-agent-proof.txt\"}"}}]}}]}` + "\n\n" +
		"data: " + `{"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}` + "\n\n" +
		"data: [DONE]\n\n")
	msg, err := parseAssistant(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.ToolCalls) != 1 || msg.ToolCalls[0].Function.Name != "files_write" {
		t.Fatalf("%+v", msg.ToolCalls)
	}
	if !strings.Contains(msg.ToolCalls[0].Function.Arguments, "pi-agent-proof.txt") {
		t.Fatalf("arguments %q", msg.ToolCalls[0].Function.Arguments)
	}
}

func TestValidateGatewayURLRejectsSecrets(t *testing.T) {
	if err := validateGatewayURL("http://x/sk-live"); err == nil {
		t.Fatal("credential URL")
	}
	if err := validateGatewayURL("http://user:pass@x/v1"); err == nil {
		t.Fatal("userinfo")
	}
	if err := validateGatewayURL("http://x/v1?api-key=1"); err == nil {
		t.Fatal("query")
	}
}
