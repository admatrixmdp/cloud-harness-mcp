package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

type fakeRunner struct {
	catalog     catalogView
	credentials credentialsView
	calls       []protocol.Operation
}

func (f *fakeRunner) Call(_ context.Context, op protocol.Operation, input json.RawMessage) protocol.ToolResult {
	f.calls = append(f.calls, op)
	switch op {
	case protocol.OpMCPGatewayCatalog:
		var filter struct {
			QualifiedName string `json:"qualifiedName"`
		}
		_ = json.Unmarshal(input, &filter)
		view := f.catalog
		if filter.QualifiedName != "" {
			filtered := catalogView{}
			for _, tool := range view.Tools {
				if tool.QualifiedName == filter.QualifiedName {
					filtered.Tools = append(filtered.Tools, tool)
					for _, server := range view.Servers {
						if server.ID == tool.ServerID {
							filtered.Servers = append(filtered.Servers, server)
						}
					}
				}
			}
			view = filtered
		}
		return protocol.Success("catalog", view)
	case protocol.OpMCPServerGetCredentials:
		return protocol.Success("credentials", f.credentials)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unexpected "+string(op), false)
	}
}

func sampleCatalog(endpoint string, enabled bool, perm protocol.GatewayPermission) catalogView {
	return catalogView{
		Servers: []catalogServer{{
			ID: "mcps_abcdefghijklmnopqrstuvwx", Name: "github", Enabled: enabled, Endpoint: endpoint, Transport: "streamable-http",
		}},
		Tools: []catalogTool{{
			ServerID: "mcps_abcdefghijklmnopqrstuvwx", ServerName: "github", QualifiedName: "github.issue_create",
			UpstreamName: "issue_create", Description: "create an issue", Permission: string(perm), Availability: "available",
			InputSchema: map[string]any{"type": "object"},
		}},
	}
}

func TestLiveInspectUnknownAndDeniedAreTheSameNotFound(t *testing.T) {
	runner := &fakeRunner{catalog: sampleCatalog("https://example.com/mcp", true, protocol.GatewayDeny)}
	live := &Live{Runner: runner}
	unknown := live.Dispatch(context.Background(), "inspect", map[string]any{"tool": "github.nope"})
	denied := live.Dispatch(context.Background(), "inspect", map[string]any{"tool": "github.issue_create"})
	if unknown.OK || denied.OK {
		t.Fatalf("unknown=%+v denied=%+v", unknown, denied)
	}
	if unknown.Error.Code != protocol.ErrorNotFound || denied.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("codes unknown=%s denied=%s", unknown.Error.Code, denied.Error.Code)
	}
	if unknown.Error.Message != unknownToolMessage || denied.Error.Message != unknown.Error.Message {
		t.Fatalf("messages %q vs %q", unknown.Error.Message, denied.Error.Message)
	}
}

func TestLiveExecuteDeniedNeverHitsNetwork(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	t.Cleanup(srv.Close)
	runner := &fakeRunner{
		catalog:     sampleCatalog(srv.URL, true, protocol.GatewayAllow),
		credentials: credentialsView{Allowed: false, Reason: "tool_denied"},
	}
	live := &Live{Runner: runner, Endpoint: EndpointOptions{AllowInsecureHTTP: true, AllowPrivateEndpoints: true}}
	got := live.Dispatch(context.Background(), "execute", map[string]any{
		"tool":      "github.issue_create",
		"arguments": map[string]any{"secret": "must-not-echo"},
	})
	if !got.OK {
		t.Fatalf("denied execute must be ok envelope: %+v", got)
	}
	data := got.Data.(map[string]any)
	if data["allowed"] != false || data["reason"] != "tool_denied" {
		t.Fatalf("%+v", data)
	}
	if called {
		t.Fatal("denied execute must not open a socket")
	}
	if containsSecret(got) {
		t.Fatal("secret echoed")
	}
}

func TestLiveExecuteAllowPostsToolsCall(t *testing.T) {
	var seenAuth, seenBody, seenPath string
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
	runner := &fakeRunner{
		catalog: sampleCatalog(srv.URL+"/mcp", true, protocol.GatewayAllow),
		credentials: credentialsView{
			Allowed: true, Endpoint: srv.URL + "/mcp",
			Headers: map[string]string{"Authorization": "Bearer super-secret-token"},
		},
	}
	live := &Live{Runner: runner, Endpoint: EndpointOptions{
		AllowInsecureHTTP: true, AllowPrivateEndpoints: true,
		Resolve: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil },
	}}
	got := live.Dispatch(context.Background(), "execute", map[string]any{
		"tool": "github.issue_create", "arguments": map[string]any{"title": "hello"},
	})
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	if seenAuth != "Bearer super-secret-token" {
		t.Fatalf("auth %q", seenAuth)
	}
	if seenPath != "/mcp" {
		t.Fatalf("path %s", seenPath)
	}
	if !strings.Contains(seenBody, `"method":"tools/call"`) || !strings.Contains(seenBody, `"name":"issue_create"`) {
		t.Fatalf("body %s", seenBody)
	}
	if strings.Contains(got.Message, "super-secret-token") {
		t.Fatal("secret leaked")
	}
}

func TestLiveDisabledServerIsNotFoundBeforeCredentials(t *testing.T) {
	runner := &fakeRunner{catalog: sampleCatalog("https://example.com/mcp", false, protocol.GatewayAllow)}
	live := &Live{Runner: runner}
	got := live.Dispatch(context.Background(), "execute", map[string]any{"tool": "github.issue_create", "arguments": map[string]any{}})
	if got.OK || got.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("%+v", got)
	}
	for _, op := range runner.calls {
		if op == protocol.OpMCPServerGetCredentials {
			t.Fatal("disabled server must not resolve credentials")
		}
	}
}
