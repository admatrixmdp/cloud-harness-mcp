package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestExecuteDeniedNeverHitsNetwork(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	t.Cleanup(srv.Close)
	endpoint, _ := url.Parse(srv.URL)
	reg := NewRegistry(DownstreamTool{Server: "github", Name: "delete", Permission: protocol.GatewayDeny})
	reg.Client = &DownstreamClient{Endpoint: endpoint, Headers: map[string]string{"Authorization": "Bearer super-secret-token"}}
	got := reg.Execute("github.delete", map[string]any{"secret": "must-not-echo"})
	if got.OK || got.Error.Code != protocol.ErrorForbidden {
		t.Fatalf("%+v", got)
	}
	if called {
		t.Fatal("denied execute must not open a socket")
	}
	if containsSecret(got) {
		t.Fatal("secret echoed")
	}
}

func TestExecuteAllowPostsToolsCallWithoutRedirect(t *testing.T) {
	var seenAuth string
	var seenBody string
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		seenBody = string(raw)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"ok": true, "message": "ok", "truncated": false, "data": map[string]any{"n": 1}},
		})
	}))
	t.Cleanup(srv.Close)
	endpoint, _ := url.Parse(srv.URL + "/mcp")
	reg := NewRegistry(DownstreamTool{Server: "github", Name: "search_issues", Permission: protocol.GatewayAllow})
	reg.Client = &DownstreamClient{Endpoint: endpoint, Headers: map[string]string{"Authorization": "Bearer super-secret-token"}}
	got := reg.Execute("github.search_issues", map[string]any{"q": "bug"})
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	if seenAuth != "Bearer super-secret-token" {
		t.Fatalf("auth %q", seenAuth)
	}
	if seenPath != "/mcp" {
		t.Fatalf("path %s", seenPath)
	}
	if !strings.Contains(seenBody, `"method":"tools/call"`) {
		t.Fatalf("body %s", seenBody)
	}
}

func TestExecuteRefusesRedirect(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("redirect target must not be followed")
	}))
	t.Cleanup(final.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	endpoint, _ := url.Parse(srv.URL)
	reg := NewRegistry(DownstreamTool{Server: "github", Name: "search_issues", Permission: protocol.GatewayAllow})
	reg.Client = &DownstreamClient{Endpoint: endpoint, Headers: map[string]string{"Authorization": "Bearer super-secret-token"}}
	got := reg.Execute("github.search_issues", map[string]any{})
	if got.OK || got.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(got.Error.Message, "HTTP redirects are refused") {
		t.Fatalf("message %s", got.Error.Message)
	}
	if strings.Contains(got.Error.Message, "super-secret-token") {
		t.Fatal("secret leaked")
	}
}

func TestCredentialsStayOnConfiguredPath(t *testing.T) {
	var otherAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"ok": true, "message": "ok", "truncated": false}})
	})
	mux.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) {
		otherAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	endpoint, _ := url.Parse(srv.URL + "/mcp")
	client := DownstreamClient{Endpoint: endpoint, Headers: map[string]string{"Authorization": "Bearer super-secret-token"}, HTTP: srv.Client()}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/other", strings.NewReader(`{}`))
	attachHeaders(req, endpoint, client.Headers)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if otherAuth != "" && req.Header.Get("Authorization") != "" && IsConfiguredEndpoint(srv.URL+"/other", endpoint) {
		t.Fatal("other path considered configured")
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("credential attached to non-endpoint path")
	}
}
