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
