package protocol

import (
	"encoding/json"
	"testing"
)

func TestAllOperationsMatchCatalogCount(t *testing.T) {
	if len(AllOperations) != 92 {
		t.Fatalf("AllOperations = %d, want 92 public MCP tools", len(AllOperations))
	}
	seen := map[Operation]struct{}{}
	for _, op := range AllOperations {
		if !op.Known() {
			t.Fatalf("unknown operation %q", op)
		}
		if op.Internal() {
			t.Fatalf("internal operation %q must not appear in AllOperations", op)
		}
		if _, dup := seen[op]; dup {
			t.Fatalf("duplicate operation %q", op)
		}
		seen[op] = struct{}{}
	}
	if !OpMCPGatewayCatalog.Internal() || OpMCPGatewayCatalog.Known() {
		t.Fatal("mcp_gateway_catalog must be runner-internal, not a public /mcp tool")
	}
	if !OpMCPServerSetPermissions.Internal() || OpMCPServerSetPermissions.Known() {
		t.Fatal("mcp_server_set_permissions must be runner-internal, not a public /mcp tool")
	}
	if !OpMCPGatewayTraceAppend.Internal() || OpMCPGatewayTraceAppend.Known() || !OpMCPGatewayTraceList.Internal() || OpMCPGatewayTraceList.Known() {
		t.Fatal("mcp_gateway_trace_* must be runner-internal, not a public /mcp tool")
	}
	if !OpPrivilegeGrantList.Dashboard() || OpPrivilegeGrantList.Known() || OpPrivilegeGrantList.Internal() {
		t.Fatal("privilege_grant_list must be dashboard-only, not a public /mcp tool")
	}
	if !OpPrivilegeGrantApprove.Dashboard() || !OpPrivilegeGrantReject.Dashboard() {
		t.Fatal("privilege_grant_approve/reject must be dashboard-only")
	}
	if !OpWorkspaceDetail.Dashboard() || OpWorkspaceDetail.Known() || OpWorkspaceDetail.Internal() {
		t.Fatal("workspace_detail must be dashboard-only, not a public /mcp tool")
	}
	if !OpWorkspaceCloseFenced.Dashboard() || OpWorkspaceCloseFenced.Known() {
		t.Fatal("workspace_close_fenced must be dashboard-only")
	}
}

func TestOperationJSONIsBareString(t *testing.T) {
	raw, err := json.Marshal(OpWorkspaceOpen)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `"workspace_open"` {
		t.Fatalf("got %s", raw)
	}
}

func TestHints(t *testing.T) {
	if !OpFilesRead.ReadOnly() || OpFilesWrite.ReadOnly() {
		t.Fatal("files_read must be read-only; files_write must not")
	}
	if !OpGitPush.Destructive() || OpGitStatus.Destructive() {
		t.Fatal("git_push is destructive; git_status is not")
	}
	if !OpWorkspaceOpen.OpenWorld() || OpFilesList.OpenWorld() {
		t.Fatal("workspace_open is open-world; files_list is not")
	}
}

func TestNetworkAndExposure(t *testing.T) {
	if NetworkProfile("bridge").Valid() {
		t.Fatal("bridge must not be selectable")
	}
	if !ExposureLocalHost.Valid() || !DependencyAccess.Valid() {
		t.Fatal("local-host exposure and dependency-access profile must be valid")
	}
}

func TestOpaqueAndAPIKeyIDs(t *testing.T) {
	if !ValidOpaqueID(PrefixWorkspace, "ws_abcdefghijklmnopqrst") {
		t.Fatal("workspace id")
	}
	if !ValidOpaqueID(PrefixMCPServer, "mcps_abcdefghijklmnopqrst") {
		t.Fatal("gateway server id")
	}
	if !ValidAPIKeyID("apk_abcdefghijklmnopqrstuvwx") {
		t.Fatal("api key id")
	}
	if ValidAPIKeyValue("not-a-key") {
		t.Fatal("invalid api key value accepted")
	}
	if !ValidIdempotencyKey("open-repo-001") {
		t.Fatal("idempotency key")
	}
	id := NewOpaqueID(PrefixWorkspace)
	if !ValidOpaqueID(PrefixWorkspace, id) {
		t.Fatalf("generated id %q is invalid", id)
	}
}

func TestSecretPolicy(t *testing.T) {
	if err := ValidateSecretName("GH_TOKEN"); err != nil {
		t.Fatalf("GH_TOKEN must be allowed: %v", err)
	}
	if err := ValidateSecretName("GITHUB_TOKEN"); err != nil {
		t.Fatalf("GITHUB_TOKEN must be allowed: %v", err)
	}
	if err := ValidateSecretName("DOCKER_HOST"); err == nil {
		t.Fatal("DOCKER_HOST must be reserved")
	}
	if err := ValidateSecretName("HARNESS_FOO"); err == nil {
		t.Fatal("HARNESS_ prefix must be reserved")
	}
	if err := ValidateSecretValue("abcd"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecretValue("x"); err == nil {
		t.Fatal("short secret value must fail")
	}
}

func TestGatewayQualifiedName(t *testing.T) {
	if got := QualifiedToolName("github", "search"); got != "github.search" {
		t.Fatalf("got %q", got)
	}
	if !ValidQualifiedToolName("github.search") {
		t.Fatal("expected valid qualified name")
	}
	if ValidQualifiedToolName(".search") || ValidQualifiedToolName("GitHub.search") {
		t.Fatal("invalid names accepted")
	}
}

func TestGatewayToolSet(t *testing.T) {
	if len(GatewayTools) != 5 {
		t.Fatalf("gateway tools = %d", len(GatewayTools))
	}
}

func TestRunnerRequestJSON(t *testing.T) {
	req := RunnerRequest{
		Version:   2,
		Operation: OpWorkspaceOpen,
		Input:     json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp"}`),
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "operation", "input"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing %q in %s", key, raw)
		}
	}
	if got["operation"] != "workspace_open" {
		t.Fatalf("operation = %v", got["operation"])
	}
}
