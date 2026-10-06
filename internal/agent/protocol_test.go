package agent

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

type bufCloser struct{ *bytes.Buffer }

func (bufCloser) Close() error { return nil }

func TestEncodeDecodeStartAndTerminal(t *testing.T) {
	var buf bytes.Buffer
	start := StartRecord{
		Type: "start", RequestID: "req-1", AgentID: "agent_" + strings.Repeat("a", 24),
		Prompt: "secret prompt", Tools: []string{"files_list"},
		Gateway: StartGateway{Profile: "coding-fast", Lease: "lease_secret_token_value_xxxxxxxxxxxx"},
		Model:   StartModel{ID: "gpt", Name: "gpt", API: "openai-completions", ContextWindow: 8_000, MaxTokens: 1_024},
		Limits:  StartLimits{DeadlineMs: 60_000, MaxEvents: 100, MaxOutputBytes: 1024, MaxEventBytes: 1024, MaxToolResultBytes: 1024},
	}
	if err := EncodeRecord(&buf, start); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	if !strings.Contains(raw, "secret prompt") || !strings.Contains(raw, "lease_secret") {
		t.Fatal("wire must carry prompt and lease")
	}
	redacted := RedactProtocolJSON(raw)
	if strings.Contains(redacted, "secret prompt") || strings.Contains(redacted, "lease_secret") {
		t.Fatalf("redact leaked: %s", redacted)
	}
	ch := NewChannel(bufCloser{new(bytes.Buffer)}, bytes.NewReader([]byte(`{"type":"terminal","state":"SUCCEEDED","usage":{"input":1,"output":1,"cacheRead":0,"cacheWrite":0,"total":2,"cost":0}}`+"\n")))
	got, err := ch.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "terminal" || got.State != "SUCCEEDED" {
		t.Fatalf("%+v", got)
	}
}

func TestDecodeRejectsUnknownAndPartial(t *testing.T) {
	if _, err := DecodeOutput([]byte(`{"type":"nope"}`)); err == nil {
		t.Fatal("unknown type")
	}
	ch := NewChannel(bufCloser{new(bytes.Buffer)}, bytes.NewReader([]byte(`{"type":"terminal"`)))
	if _, err := ch.Recv(); err == nil {
		t.Fatal("partial")
	}
	if _, err := DecodeOutput(bytes.Repeat([]byte("a"), MaxProtocolRecordBytes+1)); err == nil {
		t.Fatal("oversize")
	}
}

func TestChannelSendClosed(t *testing.T) {
	in := bufCloser{new(bytes.Buffer)}
	ch := NewChannel(in, bytes.NewReader(nil))
	ch.CloseInput()
	if err := ch.Send(CancelRecord{Type: "cancel", RequestID: "r1"}); err == nil {
		t.Fatal("closed send")
	}
	if _, err := NewChannel(bufCloser{new(bytes.Buffer)}, bytes.NewReader(nil)).Recv(); err != io.EOF {
		t.Fatalf("eof %v", err)
	}
}
