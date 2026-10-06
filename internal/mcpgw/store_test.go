package mcpgw

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestStorePersistsCatalogAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcpgw.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	create, _ := json.Marshal(map[string]any{
		"name": "github", "transport": "streamable-http", "endpoint": "https://example.com/mcp",
		"headers":           []map[string]any{{"name": "authorization", "value": "Bearer persist-token"}},
		"permissionDefault": "deny", "enabled": true, "expectedGeneration": 0,
	})
	created := store.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerCreate, Input: create})
	if !created.OK {
		t.Fatalf("create: %+v", created)
	}
	id := created.Data.(map[string]any)["id"].(string)
	replace, _ := json.Marshal(map[string]any{
		"serverId": id, "status": "connected", "cap": 500,
		"tools": []map[string]any{{"upstreamName": "issue_create", "description": "create", "availability": "available"}},
	})
	if got := store.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerReplaceTools, Input: replace}); !got.OK {
		t.Fatalf("replace: %+v", got)
	}
	set, _ := json.Marshal(map[string]any{
		"serverId": id, "permissionDefault": "deny", "expectedGeneration": 1,
		"tools": []map[string]any{{"name": "issue_create", "permission": "allow"}},
	})
	if got := store.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerSetPermissions, Input: set}); !got.OK {
		t.Fatalf("set: %+v", got)
	}
	_ = db.Close()

	reopen, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopen.Close() })
	again, err := Open(reopen)
	if err != nil {
		t.Fatal(err)
	}
	catalog := again.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPGatewayCatalog, Input: json.RawMessage(`{}`)})
	if !catalog.OK {
		t.Fatalf("catalog: %+v", catalog)
	}
	data := catalog.Data.(map[string]any)
	tools, _ := data["tools"].([]map[string]any)
	if len(tools) != 1 || tools[0]["permission"] != "allow" {
		t.Fatalf("persisted tools %+v", data["tools"])
	}
	other := again.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-b", Operation: protocol.OpMCPGatewayCatalog, Input: json.RawMessage(`{}`)})
	otherTools, _ := other.Data.(map[string]any)["tools"].([]map[string]any)
	if len(otherTools) != 0 {
		t.Fatal("principal isolation failed after reopen")
	}
	creds := again.Handle(protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerGetCredentials,
		Input: json.RawMessage(`{"serverId":"` + id + `","toolName":"issue_create","purpose":"execute"}`),
	})
	if !creds.OK {
		t.Fatalf("creds: %+v", creds)
	}
	headers := creds.Data.(map[string]any)["headers"].(map[string]string)
	if headers["authorization"] != "Bearer persist-token" {
		t.Fatalf("headers %+v", headers)
	}
}

func TestStoreRecordsConnectionResultWithoutLeakingSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcpgw.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	create, _ := json.Marshal(map[string]any{
		"name": "github", "transport": "streamable-http", "endpoint": "https://example.com/mcp",
		"headers":           []map[string]any{{"name": "authorization", "value": "Bearer persist-token"}},
		"permissionDefault": "deny", "enabled": true, "expectedGeneration": 0,
	})
	created := store.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerCreate, Input: create})
	if !created.OK {
		t.Fatalf("create: %+v", created)
	}
	id := created.Data.(map[string]any)["id"].(string)
	raw, _ := json.Marshal(map[string]any{
		"serverId": id, "status": "error", "error": "Authorization: Bearer persist-token refused",
	})
	got := store.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerConnectionResult, Input: raw})
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	data := got.Data.(map[string]any)
	errText, _ := data["lastError"].(string)
	if strings.Contains(errText, "persist-token") {
		t.Fatalf("secret leaked in lastError %q", errText)
	}
	if data["status"] != "error" || !strings.Contains(errText, "[REDACTED]") {
		t.Fatalf("%+v", data)
	}
	if protocol.OpMCPServerConnectionResult.Known() || !protocol.OpMCPServerConnectionResult.Internal() {
		t.Fatal("mcp_server_connection_result must stay runner-internal")
	}
}

func TestStorePersistsTracesAndScrubsSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcpgw.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	secret := "s3cr3t/value+token"
	appendRaw, _ := json.Marshal(map[string]any{
		"serverId": "mcps_abcdefghijklmnopqrstuvwx", "serverName": "github", "tool": "github.issue_create",
		"operation": "execute", "clientId": "client-1", "durationMs": 15, "status": "error",
		"errorCode":    "EXECUTION_FAILED",
		"errorMessage": "upstream rejected request\nAuthorization: Bearer " + secret + "\nbody: " + secret,
		"requestBytes": 12, "responseBytes": 34, "secrets": []string{secret},
	})
	appended := store.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPGatewayTraceAppend, Input: appendRaw})
	if !appended.OK {
		t.Fatalf("append: %+v", appended)
	}
	trace := appended.Data.(map[string]any)["trace"].(map[string]any)
	id := trace["id"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixMCPTrace, id) {
		t.Fatalf("trace id %s", id)
	}
	_ = db.Close()

	reopen, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopen.Close() })
	again, err := Open(reopen)
	if err != nil {
		t.Fatal(err)
	}
	listed := again.Handle(protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPGatewayTraceList,
		Input: json.RawMessage(`{"serverId":"mcps_abcdefghijklmnopqrstuvwx","limit":50}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	raw, _ := json.Marshal(listed)
	if strings.Contains(string(raw), secret) {
		t.Fatal("persisted trace leaked secret")
	}
	if !strings.Contains(string(raw), "Authorization: [REDACTED]") {
		t.Fatalf("header not redacted: %s", raw)
	}
	if !strings.Contains(string(raw), "[REDACTED_SECRET]") {
		t.Fatalf("secret form not redacted: %s", raw)
	}
	other := again.Handle(protocol.RunnerRequest{Version: 2, OwnerID: "owner-b", Operation: protocol.OpMCPGatewayTraceList, Input: json.RawMessage(`{"limit":50}`)})
	otherTraces, _ := other.Data.(map[string]any)["traces"].([]map[string]any)
	if len(otherTraces) != 0 {
		t.Fatal("principal isolation failed for traces")
	}
}
