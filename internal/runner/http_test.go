package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
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

func TestAPIKeyRPCCreateListRevokeAndAuthenticate(t *testing.T) {
	path := t.TempDir() + "/state.sqlite"
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, st, nil)
	srv := httptest.NewServer(Handler(Options{Service: svc}))
	t.Cleanup(srv.Close)

	principal, _ := json.Marshal(protocol.OwnerPrincipal{Kind: protocol.PrincipalOwner, OwnerID: "owner"})
	createBody, _ := json.Marshal(map[string]any{
		"version": 1, "principal": json.RawMessage(principal), "operation": "api_key_create",
		"input": map[string]any{"name": "CLI", "expiresInDays": 30},
	})
	res, err := http.Post(srv.URL+"/v1/internal/api-keys", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("create status %d", res.StatusCode)
	}
	var created struct {
		OK   bool `json:"ok"`
		Data struct {
			Key    map[string]any `json:"key"`
			APIKey string         `json:"apiKey"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if !created.OK || !protocol.ValidAPIKeyValue(created.Data.APIKey) {
		t.Fatalf("create %+v", created)
	}
	id, _ := created.Data.Key["id"].(string)

	listBody, _ := json.Marshal(map[string]any{
		"version": 1, "principal": json.RawMessage(principal), "operation": "api_key_list", "input": map[string]any{},
	})
	listed, err := http.Post(srv.URL+"/v1/internal/api-keys", "application/json", bytes.NewReader(listBody))
	if err != nil {
		t.Fatal(err)
	}
	defer listed.Body.Close()
	raw, _ := io.ReadAll(listed.Body)
	if listed.StatusCode != 200 || !bytes.Contains(raw, []byte(id)) {
		t.Fatalf("list %d %s", listed.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte(created.Data.APIKey)) {
		t.Fatalf("list leaked plaintext %s", raw)
	}

	authBody, _ := json.Marshal(map[string]any{"version": 1, "apiKey": created.Data.APIKey})
	authRes, err := http.Post(srv.URL+"/v1/internal/api-keys", "application/json", bytes.NewReader(authBody))
	if err != nil {
		t.Fatal(err)
	}
	defer authRes.Body.Close()
	var auth struct {
		OK   bool `json:"ok"`
		Data struct {
			KeyID     string         `json:"keyId"`
			Principal map[string]any `json:"principal"`
		} `json:"data"`
	}
	if err := json.NewDecoder(authRes.Body).Decode(&auth); err != nil {
		t.Fatal(err)
	}
	if authRes.StatusCode != 200 || !auth.OK || auth.Data.KeyID != id {
		t.Fatalf("auth %+v status %d", auth, authRes.StatusCode)
	}

	revokeBody, _ := json.Marshal(map[string]any{
		"version": 1, "principal": json.RawMessage(principal), "operation": "api_key_revoke",
		"input": map[string]any{"keyId": id, "expectedGeneration": 1},
	})
	revoked, err := http.Post(srv.URL+"/v1/internal/api-keys", "application/json", bytes.NewReader(revokeBody))
	if err != nil {
		t.Fatal(err)
	}
	defer revoked.Body.Close()
	if revoked.StatusCode != 200 {
		t.Fatalf("revoke %d", revoked.StatusCode)
	}
	denied, err := http.Post(srv.URL+"/v1/internal/api-keys", "application/json", bytes.NewReader(authBody))
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked auth %d", denied.StatusCode)
	}
}
