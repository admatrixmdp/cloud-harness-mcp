package gateway

import (
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestListedToolsAreConstant(t *testing.T) {
	reg := NewRegistry(DownstreamTool{Server: "github", Name: "search_issues", Description: "search issues", Permission: protocol.GatewayAllow})
	listed := ListedTools()
	if len(listed) != 5 {
		t.Fatalf("%v", listed)
	}
	for _, name := range listed {
		if name == "github.search_issues" {
			t.Fatal("downstream tools must not appear in tools/list")
		}
	}
	_ = reg
}

func TestSearchInspectPermissions(t *testing.T) {
	reg := NewRegistry(DownstreamTool{
		Server:      "github",
		Name:        "search_issues",
		Description: "search GitHub issues",
		Permission:  protocol.GatewayAllow,
	})
	got := reg.Search("issues", "", 5)
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	ins := reg.Inspect("github.search_issues")
	if !ins.OK {
		t.Fatalf("%+v", ins)
	}
	denied := NewRegistry(DownstreamTool{Server: "github", Name: "delete", Permission: protocol.GatewayDeny})
	ex := denied.Execute("github.delete", map[string]any{"secret": "must-not-echo"})
	if ex.OK || ex.Error.Code != protocol.ErrorForbidden {
		t.Fatalf("denied execute: %+v", ex)
	}
	if ex.Error != nil && containsSecret(ex) {
		t.Fatal("secret echoed")
	}
}

func TestExecuteAllowIsUnavailableUntilWired(t *testing.T) {
	reg := NewRegistry(DownstreamTool{Server: "github", Name: "search_issues", Permission: protocol.GatewayAllow})
	got := reg.Execute("github.search_issues", map[string]any{})
	if got.OK || got.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("%+v", got)
	}
}

func TestStatusDoesNotListDownstreamNames(t *testing.T) {
	reg := NewRegistry(DownstreamTool{Server: "github", Name: "search_issues", Permission: protocol.GatewayAllow})
	got := reg.Status()
	data, _ := got.Data.(map[string]any)
	listed, _ := data["listedTools"].([]string)
	for _, name := range listed {
		if name == "github.search_issues" {
			t.Fatal("status leaked downstream tool")
		}
	}
}

func containsSecret(result protocol.ToolResult) bool {
	return result.Message == "must-not-echo" || (result.Error != nil && result.Error.Message == "must-not-echo")
}
