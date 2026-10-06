package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func seedGateway(t *testing.T, svc *Service, owner, name, endpoint, perm string, headers map[string]string) string {
	t.Helper()
	headerList := make([]map[string]any, 0, len(headers))
	for k, v := range headers {
		headerList = append(headerList, map[string]any{"name": k, "value": v})
	}
	raw, _ := json.Marshal(map[string]any{
		"name":               name,
		"transport":          "streamable-http",
		"endpoint":           endpoint,
		"headers":            headerList,
		"permissionDefault":  perm,
		"enabled":            true,
		"expectedGeneration": 0,
	})
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: owner, Operation: protocol.OpMCPServerCreate, Input: raw,
	})
	if !got.OK {
		t.Fatalf("create: %+v", got)
	}
	data := got.Data.(map[string]any)
	id, _ := data["id"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, id) {
		t.Fatalf("id %q", id)
	}
	return id
}

func replaceTool(t *testing.T, svc *Service, owner, serverID, upstream, perm string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"serverId": serverID,
		"status":   "connected",
		"cap":      500,
		"tools": []map[string]any{{
			"upstreamName": upstream,
			"description":  "create an issue",
			"inputSchema":  map[string]any{"type": "object"},
			"availability": "available",
		}},
	})
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: owner, Operation: protocol.OpMCPServerReplaceTools, Input: raw,
	})
	if !got.OK {
		t.Fatalf("replace: %+v", got)
	}
	if perm == string(protocol.GatewayDeny) {
		status := svc.Execute(context.Background(), protocol.RunnerRequest{
			Version: 2, OwnerID: owner, Operation: protocol.OpMCPGatewayCatalog,
			Input: json.RawMessage(`{"serverId":"` + serverID + `"}`),
		})
		if !status.OK {
			t.Fatalf("catalog for generation: %+v", status)
		}
		servers, _ := status.Data.(map[string]any)["servers"].([]any)
		if len(servers) == 0 {
			t.Fatal("missing server after replace")
		}
		generation := asInt(servers[0].(map[string]any)["generation"])
		raw, _ := json.Marshal(map[string]any{
			"serverId":           serverID,
			"permissionDefault":  perm,
			"expectedGeneration": generation,
			"tools":              []map[string]any{{"name": upstream, "permission": perm}},
		})
		set := svc.Execute(context.Background(), protocol.RunnerRequest{
			Version: 2, OwnerID: owner, Operation: protocol.OpMCPServerSetPermissions, Input: raw,
		})
		if !set.OK {
			t.Fatalf("set permissions: %+v", set)
		}
	}
}

func TestInternalGatewayOpsStayOffPublicCatalog(t *testing.T) {
	if protocol.OpMCPGatewayCatalog.Known() || protocol.OpMCPServerGetCredentials.Known() || protocol.OpMCPGatewayTraceAppend.Known() || protocol.OpMCPGatewayTraceList.Known() {
		t.Fatal("internal MCP gateway ops must not be public /mcp tools")
	}
	if protocol.OpMCPServerList.Known() || protocol.OpMCPServerGet.Known() || protocol.OpMCPServerUpdate.Known() || protocol.OpMCPServerDelete.Known() || protocol.OpMCPServerSetEnabled.Known() {
		t.Fatal("dashboard MCP server ops must not be public /mcp tools")
	}
	if protocol.OpKnowledgeDashboardList.Known() || protocol.OpKnowledgeDashboardCreate.Known() {
		t.Fatal("knowledge_dashboard_* must not be public /mcp tools")
	}
	if protocol.OpArtifactList.Known() || protocol.OpArtifactSnapshot.Known() || protocol.OpArtifactRead.Known() || protocol.OpArtifactRestore.Known() || protocol.OpArtifactDelete.Known() {
		t.Fatal("dashboard artifact_* aliases must not be public /mcp tools")
	}
	if protocol.OpAuditList.Known() || !protocol.OpAuditList.Dashboard() {
		t.Fatal("audit_list must not be a public /mcp tool")
	}
	if protocol.OpGitHubStatus.Known() || protocol.OpGitHubSetupBegin.Known() || protocol.OpGitHubDisconnect.Known() {
		t.Fatal("github_* dashboard ops must not be public /mcp tools")
	}
	if len(protocol.AllOperations) != 92 {
		t.Fatalf("AllOperations = %d", len(protocol.AllOperations))
	}
}

func TestDashboardMCPServerLifecycle(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	id := seedGateway(t, svc, "owner-a", "github", "https://example.com/mcp", "allow", map[string]string{"authorization": "Bearer super-secret-token"})
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerList, Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	servers, _ := listed.Data.(map[string]any)["servers"].([]map[string]any)
	if len(servers) != 1 || servers[0]["id"] != id {
		t.Fatalf("list data %+v", listed.Data)
	}
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerGet,
		Input: json.RawMessage(`{"serverId":"` + id + `"}`),
	})
	if !got.OK {
		t.Fatalf("get: %+v", got)
	}
	data := got.Data.(map[string]any)
	if _, ok := data["tools"]; !ok {
		t.Fatal("get must include tools")
	}
	updated := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerUpdate,
		Input: json.RawMessage(`{"serverId":"` + id + `","expectedGeneration":1,"name":"github-renamed"}`),
	})
	if !updated.OK {
		t.Fatalf("update: %+v", updated)
	}
	stale := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerSetEnabled,
		Input: json.RawMessage(`{"serverId":"` + id + `","enabled":false,"expectedGeneration":1}`),
	})
	if stale.OK || stale.Error == nil || stale.Error.Code != protocol.ErrorConflict {
		t.Fatalf("stale enable: %+v", stale)
	}
	disabled := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerSetEnabled,
		Input: json.RawMessage(`{"serverId":"` + id + `","enabled":false,"expectedGeneration":2}`),
	})
	if !disabled.OK {
		t.Fatalf("disable: %+v", disabled)
	}
	deleted := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerDelete,
		Input: json.RawMessage(`{"serverId":"` + id + `","expectedGeneration":3}`),
	})
	if !deleted.OK {
		t.Fatalf("delete: %+v", deleted)
	}
	missing := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerGet,
		Input: json.RawMessage(`{"serverId":"` + id + `"}`),
	})
	if missing.OK || missing.Error == nil || missing.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("deleted get: %+v", missing)
	}
}

func TestMCPGatewayCatalogAndCredentials(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	id := seedGateway(t, svc, "owner-a", "github", "https://example.com/mcp", "allow", map[string]string{"authorization": "Bearer super-secret-token"})
	replaceTool(t, svc, "owner-a", id, "issue_create", "allow")

	secretCreate, _ := json.Marshal(map[string]any{
		"name": "secreted", "transport": "streamable-http", "endpoint": "https://example.com/mcp",
		"headers":           []map[string]any{{"name": "authorization", "value": map[string]any{"secretRef": "MCP_TOKEN"}}},
		"permissionDefault": "allow", "enabled": true, "expectedGeneration": 0,
	})
	secreted := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerCreate, Input: secretCreate,
	})
	if !secreted.OK {
		t.Fatalf("secret create: %+v", secreted)
	}

	catalog := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPGatewayCatalog, Input: json.RawMessage(`{}`),
	})
	if !catalog.OK {
		t.Fatalf("%+v", catalog)
	}
	data := catalog.Data.(map[string]any)
	encoded, _ := json.Marshal(data)
	if !strings.Contains(string(encoded), `"secretRef":"MCP_TOKEN"`) {
		t.Fatal("catalog must project secretRef without a value")
	}
	secretedID := secreted.Data.(map[string]any)["id"].(string)
	creds := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerGetCredentials,
		Input: json.RawMessage(`{"serverId":"` + secretedID + `","purpose":"connect"}`),
	})
	if creds.OK || creds.Error == nil || creds.Error.Code != protocol.ErrorNotFound {
		t.Fatalf("unresolved secretRef must fail closed: %+v", creds)
	}
	if strings.Contains(creds.Message, "MCP_TOKEN") == false {
		t.Fatal("missing secret must name the reference")
	}
	if strings.Contains(string(encoded), `"kind":"secret"`) {
		if strings.Contains(string(encoded), `"value":`) && strings.Contains(string(encoded), `"secretRef":"MCP_TOKEN","value"`) {
			t.Fatal("secret header carried a value")
		}
	}
	other := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-b", Operation: protocol.OpMCPGatewayCatalog, Input: json.RawMessage(`{}`),
	})
	otherData := other.Data.(map[string]any)
	if tools, _ := otherData["tools"].([]any); len(tools) != 0 {
		t.Fatal("principal B must not see principal A catalog")
	}

	denied := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerGetCredentials,
		Input: json.RawMessage(`{"serverId":"` + id + `","toolName":"missing","purpose":"execute"}`),
	})
	if !denied.OK {
		t.Fatalf("denied must be ok envelope: %+v", denied)
	}
	deniedData := denied.Data.(map[string]any)
	if deniedData["allowed"] != false || deniedData["reason"] != "tool_denied" {
		t.Fatalf("%+v", deniedData)
	}

	allowed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerGetCredentials,
		Input: json.RawMessage(`{"serverId":"` + id + `","toolName":"issue_create","purpose":"execute"}`),
	})
	if !allowed.OK {
		t.Fatalf("%+v", allowed)
	}
	allowedData := allowed.Data.(map[string]any)
	if allowedData["allowed"] != true {
		t.Fatalf("%+v", allowedData)
	}
	switch headers := allowedData["headers"].(type) {
	case map[string]string:
		if headers["authorization"] != "Bearer super-secret-token" {
			t.Fatalf("headers %+v", headers)
		}
	case map[string]any:
		if headers["authorization"] != "Bearer super-secret-token" {
			t.Fatalf("headers %+v", headers)
		}
	default:
		t.Fatalf("headers type %T", allowedData["headers"])
	}

	connect := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner-a", Operation: protocol.OpMCPServerGetCredentials,
		Input: json.RawMessage(`{"serverId":"` + id + `","purpose":"connect"}`),
	})
	if !connect.OK {
		t.Fatalf("%+v", connect)
	}
}

func TestInternalGatewayHTTP(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	id := seedGateway(t, svc, "owner", "github", "https://example.com/mcp", "allow", nil)
	replaceTool(t, svc, "owner", id, "issue_create", "allow")
	srv := httptest.NewServer(Handler(Options{Service: svc}))
	t.Cleanup(srv.Close)
	body := []byte(`{"version":2,"ownerId":"owner","operation":"mcp_gateway_catalog","input":{}}`)
	res, err := http.Post(srv.URL+"/v1/operations", "application/json", strings.NewReader(string(body)))
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
		t.Fatalf("%+v", got)
	}
}

func TestMCPGatewayTracesScrubSecrets(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	id := seedGateway(t, svc, "owner", "github", "https://example.com/mcp", "allow", nil)
	secret := "s3cr3t/value+token"
	appendRaw, _ := json.Marshal(map[string]any{
		"serverId": id, "serverName": "github", "tool": "first", "operation": "execute",
		"durationMs": 15, "status": "error", "errorCode": "EXECUTION_FAILED",
		"errorMessage": "upstream rejected request\nAuthorization: Bearer " + secret + "\nbody: " + secret,
		"secrets":      []string{secret},
	})
	appended := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpMCPGatewayTraceAppend, Input: appendRaw,
	})
	if !appended.OK {
		t.Fatalf("append: %+v", appended)
	}
	listed := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpMCPGatewayTraceList,
		Input: json.RawMessage(`{"serverId":"` + id + `","limit":50}`),
	})
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	raw, _ := json.Marshal(listed)
	if strings.Contains(string(raw), secret) {
		t.Fatal("memory hub leaked secret")
	}
	if !strings.Contains(string(raw), "Authorization: [REDACTED]") {
		t.Fatalf("header not redacted: %s", raw)
	}
	foreign := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "other", Operation: protocol.OpMCPGatewayTraceList, Input: json.RawMessage(`{"limit":50}`),
	})
	traces, _ := foreign.Data.(map[string]any)["traces"].([]map[string]any)
	if len(traces) != 0 {
		t.Fatal("principal isolation failed for memory traces")
	}
}

func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}
