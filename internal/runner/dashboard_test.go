package runner

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/grants"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func TestDashboardPrivilegeGrantRPC(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "grants.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := grants.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create("owner", "ws_1", grants.SkillGrantCommand("tdd", "run.sh", "aa"), ".", 60_000)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithGrants(store)
	srv := httptest.NewServer(Handler(Options{ServiceToken: "runner-token", Service: svc}))
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpPrivilegeGrantList,
		Input: json.RawMessage(`{"workspaceId":"ws_1"}`),
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/internal/dashboard-operations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer runner-token")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var listed protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}

	unauth, err := http.Post(srv.URL+"/v1/internal/dashboard-operations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", unauth.StatusCode)
	}

	approveBody, _ := json.Marshal(protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpPrivilegeGrantApprove,
		Input: json.RawMessage(`{"grantId":"` + created.ID + `"}`),
	})
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/v1/internal/dashboard-operations", bytes.NewReader(approveBody))
	req.Header.Set("Authorization", "Bearer runner-token")
	req.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var approved protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&approved); err != nil {
		t.Fatal(err)
	}
	if !approved.OK {
		t.Fatalf("%+v", approved)
	}
}

func TestDashboardWorkspaceDetailAndCloseFenced(t *testing.T) {
	jobs := t.TempDir()
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone, JobsRoot: jobs}, nil, nil)
	srv := httptest.NewServer(Handler(Options{ServiceToken: "runner-token", Service: svc}))
	t.Cleanup(srv.Close)

	openBody, _ := json.Marshal(protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-dash-detail-1","networkProfile":"network-none"}`),
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/operations", bytes.NewReader(openBody))
	req.Header.Set("Authorization", "Bearer runner-token")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var opened protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&opened); err != nil || !opened.OK {
		t.Fatalf("open %+v err %v", opened, err)
	}
	id := opened.Data.(map[string]any)["workspaceId"].(string)

	detailBody, _ := json.Marshal(protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceDetail,
		Input: json.RawMessage(`{"workspaceId":"` + id + `"}`),
	})
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/v1/internal/dashboard-operations", bytes.NewReader(detailBody))
	req.Header.Set("Authorization", "Bearer runner-token")
	req.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var detail protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&detail); err != nil || !detail.OK {
		t.Fatalf("detail %+v err %v", detail, err)
	}
	if detail.Data.(map[string]any)["generation"] == nil {
		t.Fatal("detail must include generation for the cockpit fence")
	}

	staleBody, _ := json.Marshal(protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceCloseFenced,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","expectedGeneration":99}`),
	})
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/v1/internal/dashboard-operations", bytes.NewReader(staleBody))
	req.Header.Set("Authorization", "Bearer runner-token")
	req.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var stale protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&stale); err != nil {
		t.Fatal(err)
	}
	if stale.OK || stale.Error.Code != protocol.ErrorConflict {
		t.Fatalf("stale %+v", stale)
	}

	closeBody, _ := json.Marshal(protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceCloseFenced,
		Input: json.RawMessage(`{"workspaceId":"` + id + `","expectedGeneration":1}`),
	})
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/v1/internal/dashboard-operations", bytes.NewReader(closeBody))
	req.Header.Set("Authorization", "Bearer runner-token")
	req.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var closed protocol.ToolResult
	if err := json.NewDecoder(res.Body).Decode(&closed); err != nil || !closed.OK {
		t.Fatalf("close %+v err %v", closed, err)
	}
}
