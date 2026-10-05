package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
)

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{}))
	t.Cleanup(srv.Close)
	res, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestReadyzWithoutRunner(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{}))
	t.Cleanup(srv.Close)
	res, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestAccessModeIgnoresOpaqueBearer(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{Mode: auth.ModeCloudflareAccess, BearerToken: "owner-secret"}))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer owner-secret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound && res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("opaque bearer must not authenticate Access mode, got %d", res.StatusCode)
	}
}

func TestBearerRequiredWhenConfigured(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{BearerToken: "secret-token-value"}))
	t.Cleanup(srv.Close)
	res, err := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token-value")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("authed status %d", res.StatusCode)
	}
}
