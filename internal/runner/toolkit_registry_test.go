package runner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/skillsreg"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestDashboardToolkitRegistryListUpdateRefresh(t *testing.T) {
	svc := skillsService(t)
	listed := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpToolkitRegistryList, Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}
	data, _ := listed.Data.(map[string]any)
	entries, _ := data["entries"].([]map[string]any)
	if entries == nil {
		if raw, ok := data["entries"].([]any); !ok || len(raw) != 0 {
			t.Fatalf("entries %#v", data["entries"])
		}
	} else if len(entries) != 0 {
		t.Fatalf("entries %#v", entries)
	}
	if presets, _ := data["presets"].([]map[string]any); len(presets) == 0 {
		if raw, ok := data["presets"].([]any); !ok || len(raw) == 0 {
			t.Fatalf("presets %#v", data["presets"])
		}
	}

	updated := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpToolkitRegistryUpdate,
		Input: json.RawMessage(`{"provider":"skills-sh","slug":"anthropics/skills/pdf","action":"install","expectedGeneration":0}`),
	})
	if !updated.OK {
		t.Fatalf("%+v", updated)
	}
	refreshed := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpToolkitRegistryRefresh,
		Input: json.RawMessage(`{"provider":"skills-sh"}`),
	})
	if !refreshed.OK {
		t.Fatalf("%+v", refreshed)
	}
	raw, _ := json.Marshal(refreshed.Data)
	if !strings.Contains(string(raw), `"slug":"anthropics/skills/pdf"`) {
		t.Fatalf("%s", raw)
	}
	listedAfter := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpToolkitRegistryList, Input: json.RawMessage(`{}`),
	})
	listedRaw, _ := json.Marshal(listedAfter.Data)
	if strings.Contains(string(listedRaw), `"anthropics/skills/pdf"`) {
		t.Fatalf("list must not include catalogue rows %s", listedRaw)
	}
	if protocol.OpToolkitRegistryList.Known() || protocol.OpToolkitRegistryUpdate.Known() || !protocol.OpToolkitRegistryRefresh.Dashboard() {
		t.Fatal("toolkit_registry_* must stay dashboard-only")
	}
}

func TestDashboardToolkitRegistryListUsesCache(t *testing.T) {
	svc := skillsService(t)
	if err := svc.skills.UpsertCacheEntry(skillsreg.CacheEntry{
		CacheKey: "tkc_registry", OwnerID: "owner", SourceIdentity: "registry:skills-sh:anthropics/skills",
		ResolvedRevision: strings.Repeat("a", 40), AdapterVersion: 1, BundleSHA256: strings.Repeat("b", 64),
		Status: "READY", ByteCount: 1024, FileCount: 3, CreatedAt: 1, LastUsedAt: 2,
	}); err != nil {
		t.Fatal(err)
	}
	listed := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpToolkitRegistryList, Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}
	raw, _ := json.Marshal(listed.Data)
	if !strings.Contains(string(raw), `"cacheState":"READY"`) || !strings.Contains(string(raw), `"lockState":"unlocked"`) {
		t.Fatalf("%s", raw)
	}
	if strings.Contains(string(raw), `"ownerId"`) || strings.Contains(string(raw), `"bundleSha256"`) {
		t.Fatalf("leaked %s", raw)
	}
}
