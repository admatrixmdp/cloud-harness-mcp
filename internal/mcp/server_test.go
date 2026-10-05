package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestToolListMatchesProtocol(t *testing.T) {
	tools := ToolList()
	if len(tools) != len(protocol.AllOperations) {
		t.Fatalf("tools = %d, operations = %d", len(tools), len(protocol.AllOperations))
	}
	if tools[0].Name != "workspace_open" {
		t.Fatalf("first tool = %q", tools[0].Name)
	}
}

func TestToolsListRPC(t *testing.T) {
	srv := httptest.NewServer(Handler())
	t.Cleanup(srv.Close)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	res, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var payload struct {
		Result struct {
			Tools []ToolSpec `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Result.Tools) != 92 {
		t.Fatalf("listed %d tools", len(payload.Result.Tools))
	}
}

func TestGatewayListsFiveTools(t *testing.T) {
	srv := httptest.NewServer(GatewayHandler())
	t.Cleanup(srv.Close)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	res, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var payload struct {
		Result struct {
			Tools []ToolSpec `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Result.Tools) != 5 {
		t.Fatalf("gateway listed %d tools", len(payload.Result.Tools))
	}
	for _, tool := range payload.Result.Tools {
		if tool.Name == "github.search_issues" {
			t.Fatal("downstream tools must not appear in tools/list")
		}
	}
}

func TestGatewayCallStatus(t *testing.T) {
	srv := httptest.NewServer(GatewayHandler())
	t.Cleanup(srv.Close)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}}`)
	res, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var payload struct {
		Result CallToolResult `json:"result"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Result.IsError || !payload.Result.StructuredContent.OK {
		t.Fatalf("%+v", payload.Result)
	}
}

func TestToolsCallWithoutRunner(t *testing.T) {
	srv := httptest.NewServer(Handler())
	t.Cleanup(srv.Close)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"workspace_list","arguments":{}}}`)
	res, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var payload struct {
		Result CallToolResult `json:"result"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Result.IsError {
		t.Fatal("expected error when runner is missing")
	}
	if payload.Result.StructuredContent.Error == nil || payload.Result.StructuredContent.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("got %+v", payload.Result.StructuredContent)
	}
}

func TestToolsCallForwardsToRunner(t *testing.T) {
	runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/operations" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"message":"workspaces","data":{"workspaces":[]},"truncated":false}`))
	}))
	t.Cleanup(runner.Close)

	srv := httptest.NewServer(HandlerWith(HandlerOptions{Runner: &RunnerClient{BaseURL: runner.URL}}))
	t.Cleanup(srv.Close)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"workspace_list","arguments":{}}}`)
	res, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var payload struct {
		Result CallToolResult `json:"result"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Result.IsError || !payload.Result.StructuredContent.OK {
		t.Fatalf("got %+v", payload.Result)
	}
	if payload.Result.StructuredContent.Message != "workspaces" {
		t.Fatalf("message %q", payload.Result.StructuredContent.Message)
	}
}
