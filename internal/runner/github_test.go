package runner

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/audit"
	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
	"github.com/bestagentkits/cloud-harness-mcp/internal/githubapp"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

type stubGitHubVerifier struct {
	fn func(id string) (githubapp.Verified, error)
}

func (s stubGitHubVerifier) VerifyInstallation(id string) (githubapp.Verified, error) {
	if s.fn != nil {
		return s.fn(id)
	}
	return githubapp.Verified{
		AppID: "1", InstallationID: id, AccountID: id, AccountLogin: "org-" + id, Status: "active",
		Repositories: []githubapp.VerifiedRepo{{Owner: "org-" + id, Repository: "repo", Contents: "write"}},
	}, nil
}

func githubService(t *testing.T, verifier GitHubVerifier) (*Service, *githubapp.Store, *audit.Store) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "github.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := githubapp.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	aud, err := audit.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{
		NetworkProfile: protocol.NetworkNone,
		GitHubApp:      git.AppConfig{AppID: "1", AppSlug: "test-app"},
	}, nil, nil).WithGitHub(store, verifier).WithAudit(aud)
	return svc, store, aud
}

func TestDashboardGitHubStatusAndDisconnect(t *testing.T) {
	svc, store, aud := githubService(t, stubGitHubVerifier{})
	if _, err := store.ReplaceVerified("owner", githubapp.Verified{
		AppID: "1", InstallationID: "101", AccountID: "201", AccountLogin: "org-one", Status: "active",
		Repositories: []githubapp.VerifiedRepo{{Owner: "org-one", Repository: "repo1", Contents: "write"}},
	}, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReplaceVerified("owner", githubapp.Verified{
		AppID: "1", InstallationID: "102", AccountID: "202", AccountLogin: "org-two", Status: "active",
		Repositories: []githubapp.VerifiedRepo{{Owner: "org-two", Repository: "repo2", Contents: "read"}},
	}, 110); err != nil {
		t.Fatal(err)
	}
	status := svc.Execute(t.Context(), protocol.RunnerRequest{Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubStatus})
	if !status.OK {
		t.Fatalf("%+v", status)
	}
	raw, _ := json.Marshal(status.Data)
	if !bytes.Contains(raw, []byte(`"installationId":"101"`)) || !bytes.Contains(raw, []byte(`"installationId":"102"`)) {
		t.Fatalf("status %s", raw)
	}
	if bytes.Contains(raw, []byte(`"ownerId"`)) || bytes.Contains(raw, []byte(`"secretToken"`)) {
		t.Fatalf("leaked %s", raw)
	}
	disconnected := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubDisconnect,
		Input: json.RawMessage(`{"installationId":"101"}`),
	})
	if !disconnected.OK {
		t.Fatalf("%+v", disconnected)
	}
	raw, _ = json.Marshal(disconnected.Data)
	if !bytes.Contains(raw, []byte(`"installationId":"102"`)) {
		t.Fatalf("after disconnect %s", raw)
	}
	data, _ := disconnected.Data.(map[string]any)
	for _, row := range githubMaps(data["installations"]) {
		if fmt.Sprint(row["installationId"]) == "101" {
			t.Fatalf("disconnected installation still listed %s", raw)
		}
	}
	events, err := aud.List("owner", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "github.disconnected" && e.SubjectID == "101" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit %+v", events)
	}
}

func TestDashboardGitHubSetupBeginAndComplete(t *testing.T) {
	svc, _, _ := githubService(t, stubGitHubVerifier{})
	begin := svc.Execute(t.Context(), protocol.RunnerRequest{Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubSetupBegin})
	if !begin.OK {
		t.Fatalf("%+v", begin)
	}
	data, _ := begin.Data.(map[string]any)
	state, _ := data["state"].(string)
	url, _ := data["url"].(string)
	if state == "" || !bytes.Contains([]byte(url), []byte("https://github.com/apps/test-app/installations/new?state=")) {
		t.Fatalf("%v", data)
	}
	complete := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubSetupComplete,
		Input: json.RawMessage(`{"state":"` + state + `","installationId":"456"}`),
	})
	if !complete.OK {
		t.Fatalf("%+v", complete)
	}
	raw, _ := json.Marshal(complete.Data)
	if !bytes.Contains(raw, []byte(`"installationId":"456"`)) || !bytes.Contains(raw, []byte(`"org-456"`)) {
		t.Fatalf("complete %s", raw)
	}
}

func TestDashboardGitHubUnavailableWithoutBinding(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	res := svc.Execute(t.Context(), protocol.RunnerRequest{Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubSetupBegin})
	if res.OK || res.Error == nil || res.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("%+v", res)
	}
	status := svc.Execute(t.Context(), protocol.RunnerRequest{Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubStatus})
	if !status.OK {
		t.Fatalf("%+v", status)
	}
	data, _ := status.Data.(map[string]any)
	if data["configured"] != false {
		t.Fatalf("%v", data)
	}
}

func TestDashboardGitHubReconcileMarksUninstalled(t *testing.T) {
	svc, store, aud := githubService(t, stubGitHubVerifier{fn: func(string) (githubapp.Verified, error) {
		return githubapp.Verified{}, fmt.Errorf("%s: GitHub installation not found", protocol.ErrorNotFound)
	}})
	if _, err := store.ReplaceVerified("owner", githubapp.Verified{
		AppID: "1", InstallationID: "101", AccountID: "201", AccountLogin: "org-one", Status: "active",
	}, 100); err != nil {
		t.Fatal(err)
	}
	res := svc.Execute(t.Context(), protocol.RunnerRequest{Version: 2, OwnerID: "owner", Operation: protocol.OpGitHubReconcile})
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	row, err := store.GetInstallation("owner", "101")
	if err != nil || row == nil || row.Status != "uninstalled" {
		t.Fatalf("%+v %v", row, err)
	}
	events, err := aud.List("owner", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "github.uninstalled" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit %+v", events)
	}
}

func githubMaps(raw any) []map[string]any {
	switch rows := raw.(type) {
	case []map[string]any:
		return rows
	case []any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			if obj, ok := row.(map[string]any); ok {
				out = append(out, obj)
			}
		}
		return out
	default:
		return nil
	}
}

func TestGitHubOpsStayOffPublicCatalog(t *testing.T) {
	if protocol.OpGitHubStatus.Known() || protocol.OpGitHubSetupBegin.Known() || protocol.OpGitHubDisconnect.Internal() {
		t.Fatal("github_* must stay dashboard-only")
	}
	if len(protocol.AllOperations) != 92 {
		t.Fatalf("AllOperations = %d", len(protocol.AllOperations))
	}
}
