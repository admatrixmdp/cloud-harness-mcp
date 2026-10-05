package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func securityHandler(hosts, origins []string) http.Handler {
	return RequestSecurity(SecurityConfig{PublicHosts: hosts, AllowedOrigins: origins}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
}

func TestRequestSecurityRejectsUnknownHost(t *testing.T) {
	srv := httptest.NewServer(securityHandler([]string{"harness.zuey.me"}, nil))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/healthz", nil)
	req.Host = "evil.example"
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", res.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	if body["error"] != "forbidden_host" {
		t.Fatalf("%v", body)
	}
}

func TestRequestSecurityRejectsUnknownOrigin(t *testing.T) {
	srv := httptest.NewServer(securityHandler([]string{"harness.zuey.me"}, []string{"https://harness.zuey.me"}))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp", nil)
	req.Host = "harness.zuey.me"
	req.Header.Set("Origin", "https://evil.example")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", res.StatusCode)
	}
	raw, _ := io.ReadAll(res.Body)
	if !containsJSONError(raw, "forbidden_origin") {
		t.Fatalf("%s", raw)
	}
}

func TestRequestSecuritySetsHeadersOnAllow(t *testing.T) {
	srv := httptest.NewServer(securityHandler([]string{"harness.zuey.me"}, []string{"https://harness.zuey.me"}))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/healthz", nil)
	req.Host = "harness.zuey.me:443"
	req.Header.Set("Origin", "https://harness.zuey.me")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("Cache-Control")
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff")
	}
	if res.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("X-Accel-Buffering")
	}
}

func TestRequestSecurityRateLimit(t *testing.T) {
	h := RequestSecurity(SecurityConfig{PublicHosts: []string{"h.example"}, PreAuthMax: 2, PreAuthActive: 8}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://h.example/", nil)
		req.Host = "h.example"
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("req %d: %d", i, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://h.example/", nil)
	req.Host = "h.example"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rec.Code)
	}
}

func containsJSONError(raw []byte, code string) bool {
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return false
	}
	got, _ := body["error"].(string)
	return got == code
}
