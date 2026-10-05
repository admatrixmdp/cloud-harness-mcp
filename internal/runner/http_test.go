package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{Service: NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)}))
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

func TestUnknownOperation(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{Service: NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)}))
	t.Cleanup(srv.Close)
	body := []byte(`{"version":2,"operation":"not_a_tool","input":{}}`)
	res, err := http.Post(srv.URL+"/v1/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var got protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.OK || got.Error == nil || got.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("got %+v", got)
	}
}

func TestWorkspaceOpenRPC(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{Service: NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)}))
	t.Cleanup(srv.Close)
	body := []byte(`{"version":2,"operation":"workspace_open","input":{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-repo-http-1","networkProfile":"network-none"}}`)
	res, err := http.Post(srv.URL+"/v1/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	var got protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.OK {
		t.Fatalf("got %+v", got)
	}
}

func TestUnimplementedOperationUnavailable(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	open := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-unimpl-1","networkProfile":"network-none"}`),
	})
	if !open.OK {
		t.Fatalf("open: %+v", open)
	}
	id := open.Data.(map[string]any)["workspaceId"].(string)
	srv := httptest.NewServer(Handler(Options{Service: svc}))
	t.Cleanup(srv.Close)
	body := []byte(`{"version":2,"operation":"files_list","input":{"workspaceId":"` + id + `","path":"."}}`)
	res, err := http.Post(srv.URL+"/v1/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestServiceToken(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{ServiceToken: "runner-token", Service: NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)}))
	t.Cleanup(srv.Close)
	res, err := http.Post(srv.URL+"/v1/operations", "application/json", bytes.NewReader([]byte(`{"version":2,"operation":"workspace_open","input":{}}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", res.StatusCode)
	}
}
