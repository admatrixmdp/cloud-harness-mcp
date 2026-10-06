package runner

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/skillsreg"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func skillsService(t *testing.T) *Service {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "skills.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := skillsreg.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithSkills(store)
}

func TestDashboardSkillsCreateListSearchSets(t *testing.T) {
	svc := skillsService(t)
	created := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillCreateCustom,
		Input: json.RawMessage(`{"slug":"tdd","displayName":"TDD","instructions":"# TDD\nWrite the test first.","expectedGeneration":0}`),
	})
	if !created.OK {
		t.Fatalf("%+v", created)
	}
	raw, _ := json.Marshal(created.Data)
	if strings.Contains(string(raw), `"instructions"`) {
		t.Fatalf("instructions leaked %s", raw)
	}
	data, _ := created.Data.(map[string]any)
	skillID, _ := data["id"].(string)
	listed := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillList, Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}
	search := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillSearch,
		Input: json.RawMessage(`{"query":"tdd","providers":["local"]}`),
	})
	if !search.OK {
		t.Fatalf("%+v", search)
	}
	set := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillSetCreate,
		Input: json.RawMessage(`{"name":"core","expectedGeneration":0}`),
	})
	if !set.OK {
		t.Fatalf("%+v", set)
	}
	job := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillImportStart,
		Input: json.RawMessage(`{"sourceKind":"skills-sh","sourceRef":"test-driven-development","expectedGeneration":0}`),
	})
	if !job.OK {
		t.Fatalf("%+v", job)
	}
	if protocol.OpSkillList.Known() || protocol.OpSkillCreateCustom.Known() || !protocol.OpSkillSetPreview.Dashboard() {
		t.Fatal("skill dashboard ops must stay dashboard-only")
	}
	_ = skillID
}

func TestSkillOpsUnavailableWithoutStore(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	got := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillList, Input: json.RawMessage(`{}`),
	})
	if got.OK || got.Error == nil || got.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("%+v", got)
	}
}
