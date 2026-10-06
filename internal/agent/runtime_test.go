package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
