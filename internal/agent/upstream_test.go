package agent

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyRejectsPrivateUpstream(t *testing.T) {
	profile := Profile{
		ID:       "gpt-test",
		Upstream: Upstream{URL: "https://127.0.0.1/v1/chat/completions", Credential: "sk-not-a-real-key"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"x"}`))
	proxyUpstream(rec, req, profile)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-not-a-real-key") {
		t.Fatal("credential leaked")
	}
}

func TestProxyStripsRoutingFieldsAndDoesNotLogCredential(t *testing.T) {
	var seenAuth string
	var seenBody string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		seenBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","choices":[]}`))
	}))
	t.Cleanup(upstream.Close)
	profile := Profile{
		ID: "gpt-test",
		Upstream: Upstream{
			URL:              upstream.URL + "/v1/chat/completions",
			Credential:       "sk-not-a-real-key",
			CredentialHeader: "Authorization",
			CredentialScheme: "Bearer",
			AllowPrivate:     true,
			Transport:        upstream.Client().Transport,
			Timeout:          5 * time.Second,
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"x","api_key":"steal-me"}`))
	proxyUpstream(rec, req, profile)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forbidden field status %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"x"}`))
	proxyUpstream(rec, req, profile)
	if rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if seenAuth != "Bearer sk-not-a-real-key" {
		t.Fatalf("auth %q", seenAuth)
	}
	if strings.Contains(seenBody, "api_key") {
		t.Fatalf("routing field forwarded: %s", seenBody)
	}
	if strings.Contains(rec.Body.String(), "sk-not-a-real-key") {
		t.Fatal("credential leaked downstream")
	}
}

func TestProxyBlocksCredentialDisclosure(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":"sk-not-a-real-key leaked"}`))
	}))
	t.Cleanup(upstream.Close)
	profile := Profile{
		ID: "gpt-test",
		Upstream: Upstream{
			URL:          upstream.URL,
			Credential:   "sk-not-a-real-key",
			AllowPrivate: true,
			Transport:    upstream.Client().Transport,
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"x"}`))
	proxyUpstream(rec, req, profile)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sk-not-a-real-key") {
		t.Fatal("credential leaked")
	}
}
