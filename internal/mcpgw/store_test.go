package mcpgw

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
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
