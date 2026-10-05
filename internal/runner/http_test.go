package runner

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
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

func TestUnknownOperation(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{}))
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

func TestKnownOperationUnavailable(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{}))
	t.Cleanup(srv.Close)
	body := []byte(`{"version":2,"operation":"workspace_open","input":{}}`)
	res, err := http.Post(srv.URL+"/v1/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", res.StatusCode)
	}
	var got protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Error == nil || got.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("got %+v", got)
	}
}

func TestServiceToken(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{ServiceToken: "runner-token"}))
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
