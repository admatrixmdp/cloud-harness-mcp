package typesafe

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const longPrompt = "Refactor the authentication middleware so the deprecated option is removed."

func testRoster(names ...string) []RosterEntry {
	out := make([]RosterEntry, 0, len(names))
	for _, name := range names {
		out = append(out, RosterEntry{
			Name: name, Source: "owner", ContentSHA256: name + "-sha",
			IndexDescription: name + " description", DescriptionFull: name + " full description", BodyExcerpt: name + " body excerpt",
		})
	}
	return out
}

func answerJSON(choice string, nouls map[string]float64) []byte {
	answers := map[string]any{
		"skill": map[string]any{"type": "choice", "choice": choice, "confidence": 0.8, "probabilities": map[string]any{}},
	}
	for name, value := range nouls {
		answers[name] = map[string]any{"type": "noul", "noul": value}
	}
	raw, _ := json.Marshal(map[string]any{
		"model": "jev-1.13.0", "answers": answers, "usage": map[string]any{"input_tokens": 100, "output_tokens": 20},
	})
	return raw
}

func healthyGate() map[string]float64 {
	return map[string]float64{"acts_on_user_system": 1, "would_follow_documented_procedure": 1, "prose_suffices": 0}
}

func suggesterWith(t *testing.T, handler func(body []byte, call int) *http.Response, overrides Config) (*Suggester, *int) {
	t.Helper()
	calls := 0
	cfg := Config{
		APIKey: func() string { return "ts_live_key" },
		Now:    time.Now,
		RoundTrip: func(req *http.Request) (*http.Response, error) {
			calls++
			raw, _ := io.ReadAll(req.Body)
			return handler(raw, calls), nil
		},
	}
	if overrides.APIKey != nil {
		cfg.APIKey = overrides.APIKey
	}
	if overrides.Secrets != nil {
		cfg.Secrets = overrides.Secrets
	}
	if overrides.Enabled != nil {
		cfg.Enabled = overrides.Enabled
	}
	if overrides.Endpoint != "" {
		cfg.Endpoint = overrides.Endpoint
	}
	if overrides.RoundTrip != nil {
		cfg.RoundTrip = overrides.RoundTrip
	}
	return New(cfg), &calls
}

func jsonResponse(status int, body []byte) *http.Response {
	if body == nil {
		body = []byte(`{}`)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}
}

func TestParseAnswerReadsLiveShape(t *testing.T) {
	var payload any
	_ = json.Unmarshal([]byte(`{"model":"jev-1.13.0","answers":{"pick":{"type":"choice","choice":"alpha","confidence":0.82},"clear":{"type":"noul","noul":0.4}},"usage":{"input_tokens":329,"output_tokens":48}}`), &payload)
	parsed, ok := ParseAnswer(payload)
	if !ok || parsed.Choice != "alpha" || parsed.Nouls["clear"] != 0.4 || parsed.Usage.InputTokens != 329 {
		t.Fatalf("%+v ok=%v", parsed, ok)
	}
}

func TestParseAnswerUnexpectedShape(t *testing.T) {
	if _, ok := ParseAnswer(map[string]any{"answer": map[string]any{"choice": "alpha"}}); ok {
		t.Fatal("expected unexpected")
	}
	if _, ok := ParseAnswer(nil); ok {
		t.Fatal("nil")
	}
}

func TestRedactPromptReplacesSecretsAndShapes(t *testing.T) {
	secret := "super-secret-workspace-value"
	got, ok := RedactPrompt("Use "+secret+" and Bearer abcdefghijklmnopqrst for the call", map[string]string{"WORKSPACE_TOKEN": secret}, 0)
	if !ok {
		t.Fatal("redact failed")
	}
	if strings.Contains(got.Text, secret) {
		t.Fatal(got.Text)
	}
	if !strings.Contains(got.Text, "[REDACTED_SECRET: WORKSPACE_TOKEN]") || !strings.Contains(got.Text, "[REDACTED_BEARER]") {
		t.Fatal(got.Text)
	}
	if got.Count == 0 {
		t.Fatal("count")
	}
}

func TestShortCircuitSendsNothing(t *testing.T) {
	s, calls := suggesterWith(t, func([]byte, int) *http.Response {
		return jsonResponse(200, answerJSON("tdd", healthyGate()))
	}, Config{Enabled: func() bool { return false }})
	got := s.Suggest(context.Background(), "o", "", longPrompt, "d", testRoster("tdd"))
	if got.Reason != "disabled" || *calls != 0 {
		t.Fatalf("%+v calls=%d", got, *calls)
	}
	s2, calls2 := suggesterWith(t, func([]byte, int) *http.Response { t.Fatal("called"); return nil }, Config{})
	empty := s2.Suggest(context.Background(), "o", "", longPrompt, "d", nil)
	if empty.Reason != "empty_roster" || *calls2 != 0 {
		t.Fatalf("%+v", empty)
	}
	short := s2.Suggest(context.Background(), "o", "", "hi", "d", testRoster("tdd"))
	if short.Reason != "prompt_too_short" {
		t.Fatalf("%+v", short)
	}
	slash := s2.Suggest(context.Background(), "o", "", "/help", "d", testRoster("tdd"))
	if slash.Reason != "slash_command" {
		t.Fatalf("%+v", slash)
	}
}

func TestNotConfiguredAndInvalidEndpoint(t *testing.T) {
	s := New(Config{APIKey: func() string { return "" }, RoundTrip: func(*http.Request) (*http.Response, error) {
		t.Fatal("called")
		return nil, nil
	}})
	got := s.Suggest(context.Background(), "o", "", longPrompt, "d", testRoster("tdd"))
	if got.Reason != "not_configured" || got.OutboundCalls != 0 {
		t.Fatalf("%+v", got)
	}
	httpS := New(Config{APIKey: func() string { return "ts_live_key" }, Endpoint: "http://api.typesafe.ai/v1/systemone", RoundTrip: func(*http.Request) (*http.Response, error) {
		t.Fatal("called")
		return nil, nil
	}})
	invalid := httpS.Suggest(context.Background(), "o", "", longPrompt, "d", testRoster("tdd"))
	if invalid.Reason != "invalid_endpoint" {
		t.Fatalf("%+v", invalid)
	}
}

func TestHealthySuggestionNeverEchoesPrompt(t *testing.T) {
	secret := "super-secret-workspace-value"
	var seen string
	s, calls := suggesterWith(t, func(body []byte, call int) *http.Response {
		seen += string(body)
		if call == 1 {
			return jsonResponse(200, answerJSON("tdd", healthyGate()))
		}
		return jsonResponse(200, answerJSON("tdd", map[string]float64{"fits::tdd": 0.8}))
	}, Config{Secrets: func() map[string]string { return map[string]string{"WORKSPACE_TOKEN": secret} }})
	got := s.Suggest(context.Background(), "o", "ws", "Please use "+secret+" to continue the authentication middleware work.", "d", testRoster("tdd", "review"))
	if got.Suggested == nil || got.Suggested.Name != "tdd" || got.Suggested.Fit != 0.8 {
		t.Fatalf("%+v", got)
	}
	if *calls != 2 {
		t.Fatalf("calls %d", *calls)
	}
	if strings.Contains(seen, secret) {
		t.Fatal("secret in outbound body")
	}
	raw, _ := json.Marshal(got.Data())
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "authentication middleware") {
		t.Fatalf("leaked %s", raw)
	}
}

func TestBelowGateStopsAfterFirstCall(t *testing.T) {
	s, calls := suggesterWith(t, func([]byte, int) *http.Response {
		return jsonResponse(200, answerJSON("tdd", map[string]float64{"acts_on_user_system": 1, "would_follow_documented_procedure": 0, "prose_suffices": 1}))
	}, Config{})
	got := s.Suggest(context.Background(), "o", "", longPrompt, "d", testRoster("tdd", "review"))
	if got.Reason != "below_gate" || got.Suggested != nil || *calls != 1 {
		t.Fatalf("%+v calls=%d", got, *calls)
	}
}

func TestInvalidChoiceIsDiscarded(t *testing.T) {
	s, _ := suggesterWith(t, func([]byte, int) *http.Response {
		return jsonResponse(200, answerJSON("totally-made-up", healthyGate()))
	}, Config{})
	got := s.Suggest(context.Background(), "o", "", longPrompt, "d", testRoster("tdd"))
	if got.Reason != "invalid_choice" || got.Suggested != nil {
		t.Fatalf("%+v", got)
	}
}

func TestUnauthorizedMapsWithoutRetry(t *testing.T) {
	s, calls := suggesterWith(t, func([]byte, int) *http.Response { return jsonResponse(401, nil) }, Config{})
	got := s.Suggest(context.Background(), "o", "", longPrompt, "d", testRoster("tdd"))
	if got.Reason != "unauthorized" || *calls != 1 {
		t.Fatalf("%+v calls=%d", got, *calls)
	}
}

func TestRateLimitedRetriesOnce(t *testing.T) {
	s, calls := suggesterWith(t, func([]byte, int) *http.Response { return jsonResponse(429, nil) }, Config{})
	got := s.Suggest(context.Background(), "o", "", longPrompt, "d", testRoster("tdd"))
	if got.Reason != "rate_limited" || *calls != 2 {
		t.Fatalf("%+v calls=%d", got, *calls)
	}
}

func TestCacheDoesNotStorePrompt(t *testing.T) {
	s, calls := suggesterWith(t, func(_ []byte, call int) *http.Response {
		if call == 1 {
			return jsonResponse(200, answerJSON("tdd", healthyGate()))
		}
		return jsonResponse(200, answerJSON("tdd", map[string]float64{"fits::tdd": 0.9}))
	}, Config{})
	first := s.Suggest(context.Background(), "o", "ws", longPrompt, "d", testRoster("tdd"))
	second := s.Suggest(context.Background(), "o", "ws", longPrompt, "d", testRoster("tdd"))
	if first.Cached || !second.Cached || *calls != 2 {
		t.Fatalf("first=%+v second=%+v calls=%d", first, second, *calls)
	}
	s.mu.Lock()
	raw, _ := json.Marshal(s.cache)
	s.mu.Unlock()
	if strings.Contains(string(raw), longPrompt) {
		t.Fatal("cache stored prompt")
	}
}

func TestRedactionFailedSendsNothing(t *testing.T) {
	s, calls := suggesterWith(t, func([]byte, int) *http.Response { t.Fatal("called"); return nil }, Config{
		Secrets: func() map[string]string { panic("keyring unavailable") },
	})
	got := s.Suggest(context.Background(), "o", "", longPrompt, "d", testRoster("tdd"))
	if got.Reason != "redaction_failed" || *calls != 0 {
		t.Fatalf("%+v calls=%d", got, *calls)
	}
}
