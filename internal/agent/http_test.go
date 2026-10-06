package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthzAndLeaseGate(t *testing.T) {
	reg := NewRegistry()
	profile := Profile{ID: "gpt-test", Limits: ProfileLimits{MaxInputTokens: 10, MaxOutputTokens: 10, MaxCostMicros: 10}}
	h := Handler(reg, map[string]Profile{"gpt-test": profile})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != `{"ok":true}` {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	denied := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	denied.Header.Set("x-model-profile", "gpt-test")
	denied.Header.Set("x-agent-id", "agent_"+strings.Repeat("e", 24))
	denied.Header.Set("Authorization", "Bearer not-a-lease")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, denied)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "not-a-lease") {
		t.Fatal("lease echoed")
	}
	agentID := "agent_" + strings.Repeat("f", 24)
	token, err := reg.Issue(IssueInput{
		LeaseID: "lease-http", AgentID: agentID, ProfileID: "gpt-test",
		TTL: time.Minute, MaxInputTokens: 10, MaxOutputTokens: 10, MaxCostMicros: 10,
	}, profile)
	if err != nil {
		t.Fatal(err)
	}
	ok := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	ok.Header.Set("x-model-profile", "gpt-test")
	ok.Header.Set("x-agent-id", agentID)
	ok.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, ok)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected UNAVAILABLE until upstream is wired, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerProxiesAfterLease(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-not-a-real-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl"}`))
	}))
	t.Cleanup(upstream.Close)
	reg := NewRegistry()
	profile := Profile{
		ID:     "gpt-test",
		Limits: ProfileLimits{MaxInputTokens: 10_000, MaxOutputTokens: 10_000, MaxCostMicros: 1_000_000},
		Upstream: Upstream{
			URL:              upstream.URL,
			Credential:       "sk-not-a-real-key",
			CredentialHeader: "Authorization",
			CredentialScheme: "Bearer",
			AllowPrivate:     true,
			Transport:        upstream.Client().Transport,
		},
	}
	h := Handler(reg, map[string]Profile{"gpt-test": profile})
	agentID := "agent_" + strings.Repeat("c", 24)
	token, err := reg.Issue(IssueInput{
		LeaseID: "lease-proxy", AgentID: agentID, ProfileID: "gpt-test",
		TTL: time.Minute, MaxInputTokens: 10_000, MaxOutputTokens: 10_000, MaxCostMicros: 1_000_000,
	}, profile)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"x"}`))
	req.Header.Set("x-model-profile", "gpt-test")
	req.Header.Set("x-agent-id", agentID)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"cmpl"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-not-a-real-key") {
		t.Fatal("credential leaked")
	}
}
