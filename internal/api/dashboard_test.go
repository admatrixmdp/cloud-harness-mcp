package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/grants"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/internal/runner"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func dashboardFixture(t *testing.T) (http.Handler, *grants.Store) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "grants.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := grants.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := runner.NewService(runner.Config{NetworkProfile: protocol.NetworkNone, JobsRoot: t.TempDir()}, nil, nil).WithGrants(store)
	inner := httptest.NewServer(runner.Handler(runner.Options{Service: svc}))
	t.Cleanup(inner.Close)
	h := Handler(Options{
		BearerToken: "owner-secret",
		OwnerID:     "owner",
		Runner:      &mcp.RunnerClient{BaseURL: inner.URL, OwnerID: "owner"},
		Security:    SecurityConfig{PublicHosts: []string{"dashboard.example"}, AllowedOrigins: []string{"https://dashboard.example"}},
	})
	return h, store
}

func dashboardDo(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "https://dashboard.example"+path, nil)
	} else {
		r = httptest.NewRequest(method, "https://dashboard.example"+path, strings.NewReader(body))
	}
	r.Host = "dashboard.example"
	r.Header.Set("Origin", "https://dashboard.example")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestDashboardListsPrivilegeGrants(t *testing.T) {
	h, store := dashboardFixture(t)
	created, err := store.Create("owner", "ws_abcdefghijklmnopqrstuvwx", grants.SkillGrantCommand("tdd", "run.sh", "aa"), ".", 60_000)
	if err != nil {
		t.Fatal(err)
	}
	rec := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/privilege-grants?workspaceId=ws_abcdefghijklmnopqrstuvwx", "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "owner-secret") {
		t.Fatal("bearer leaked")
	}
	var got struct {
		Data struct {
			Grants []map[string]any `json:"grants"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Data.Grants) != 1 || got.Data.Grants[0]["id"] != created.ID || got.Data.Grants[0]["status"] != "PENDING" {
		t.Fatalf("%s", rec.Body.String())
	}
}

func TestDashboardApproveRequiresCSRF(t *testing.T) {
	h, store := dashboardFixture(t)
	created, err := store.Create("owner", "ws_abcdefghijklmnopqrstuvwx", grants.SkillGrantCommand("tdd", "run.sh", "aa"), ".", 60_000)
	if err != nil {
		t.Fatal(err)
	}
	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/privilege-grants/"+created.ID+"/approve", `{}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("missing csrf status %d %s", denied.Code, denied.Body.String())
	}
	if strings.Contains(denied.Body.String(), created.ID) && strings.Contains(denied.Body.String(), "csrfToken") {
		t.Fatal("csrf token leaked on deny")
	}

	session := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/session", "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if session.Code != 200 {
		t.Fatalf("session %d %s", session.Code, session.Body.String())
	}
	var sess struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(session.Body.Bytes(), &sess); err != nil || sess.CSRFToken == "" {
		t.Fatalf("session body %s", session.Body.String())
	}
	cookie := session.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "__Host-ch-dashboard=") || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Secure") {
		t.Fatalf("cookie %s", cookie)
	}
	if strings.Contains(cookie, sess.CSRFToken) {
		t.Fatal("csrf token must not be in cookie")
	}

	wrong := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/privilege-grants/"+created.ID+"/approve", `{}`, map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        strings.Split(cookie, ";")[0],
		"x-csrf-token":  "not-the-token",
	})
	if wrong.Code != http.StatusForbidden || !strings.Contains(wrong.Body.String(), "csrf_failed") {
		t.Fatalf("wrong csrf %d %s", wrong.Code, wrong.Body.String())
	}

	ok := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/privilege-grants/"+created.ID+"/approve", `{}`, map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        strings.Split(cookie, ";")[0],
		"x-csrf-token":  sess.CSRFToken,
	})
	if ok.Code != 200 {
		t.Fatalf("approve %d %s", ok.Code, ok.Body.String())
	}
	if !strings.Contains(ok.Body.String(), `"status":"APPROVED"`) {
		t.Fatalf("approve body %s", ok.Body.String())
	}
	if strings.Contains(ok.Body.String(), sess.CSRFToken) {
		t.Fatal("csrf echoed")
	}
}

func TestDashboardRejectAndOriginRequired(t *testing.T) {
	h, store := dashboardFixture(t)
	created, err := store.Create("owner", "ws_abcdefghijklmnopqrstuvwx", grants.SkillGrantCommand("tdd", "run.sh", "aa"), ".", 60_000)
	if err != nil {
		t.Fatal(err)
	}
	session := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/session", "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	var sess struct {
		CSRFToken string `json:"csrfToken"`
	}
	_ = json.Unmarshal(session.Body.Bytes(), &sess)
	cookie := strings.Split(session.Header().Get("Set-Cookie"), ";")[0]

	req := httptest.NewRequest(http.MethodPost, "https://dashboard.example/dashboard/api/v1/privilege-grants/"+created.ID+"/reject", bytes.NewReader([]byte(`{}`)))
	req.Host = "dashboard.example"
	req.Header.Set("Authorization", "Bearer owner-secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	req.Header.Set("x-csrf-token", sess.CSRFToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "origin_required") {
		t.Fatalf("missing origin %d %s", rec.Code, rec.Body.String())
	}

	ok := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/privilege-grants/"+created.ID+"/reject", `{}`, map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  sess.CSRFToken,
	})
	if ok.Code != 200 || !strings.Contains(ok.Body.String(), `"status":"REJECTED"`) {
		t.Fatalf("reject %d %s", ok.Code, ok.Body.String())
	}
}

func TestDashboardDoesNotLeakRunnerErrorText(t *testing.T) {
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":false,"message":"docker sock /var/run/docker.sock","error":{"code":"INTERNAL_ERROR","message":"docker sock /var/run/docker.sock","retryable":false},"truncated":false}`)
	}))
	t.Cleanup(inner.Close)
	h := Handler(Options{
		BearerToken: "owner-secret",
		OwnerID:     "owner",
		Runner:      &mcp.RunnerClient{BaseURL: inner.URL, OwnerID: "owner"},
		Security:    SecurityConfig{PublicHosts: []string{"dashboard.example"}, AllowedOrigins: []string{"https://dashboard.example"}},
	})
	rec := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/privilege-grants", "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "docker") || strings.Contains(rec.Body.String(), "/var/run") {
		t.Fatalf("runner text leaked: %s", rec.Body.String())
	}
}

func dashboardCSRF(t *testing.T, h http.Handler) (csrf, cookie string) {
	t.Helper()
	session := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/session", "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if session.Code != 200 {
		t.Fatalf("session %d %s", session.Code, session.Body.String())
	}
	var sess struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(session.Body.Bytes(), &sess); err != nil || sess.CSRFToken == "" {
		t.Fatalf("session body %s", session.Body.String())
	}
	return sess.CSRFToken, strings.Split(session.Header().Get("Set-Cookie"), ";")[0]
}

func TestDashboardWorkspacesAndFiles(t *testing.T) {
	h, _ := dashboardFixture(t)
	csrf, cookie := dashboardCSRF(t, h)
	auth := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	opened := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/workspaces", `{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-dash-1","networkProfile":"network-none"}`, auth)
	if opened.Code != 200 {
		t.Fatalf("open %d %s", opened.Code, opened.Body.String())
	}
	var openedBody struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(opened.Body.Bytes(), &openedBody); err != nil {
		t.Fatal(err)
	}
	id, _ := openedBody.Data["workspaceId"].(string)
	if id == "" {
		t.Fatalf("open body %s", opened.Body.String())
	}
	if _, ok := openedBody.Data["generation"]; ok {
		t.Fatal("raw generation must not reach the browser")
	}
	if _, ok := openedBody.Data["environmentId"]; ok {
		t.Fatal("environmentId must not reach the browser")
	}
	if openedBody.Data["version"] == nil {
		t.Fatalf("version missing: %s", opened.Body.String())
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces", "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), id) {
		t.Fatalf("list %d %s", listed.Code, listed.Body.String())
	}

	detail := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+id, "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if detail.Code != 200 {
		t.Fatalf("detail %d %s", detail.Code, detail.Body.String())
	}
	if strings.Contains(detail.Body.String(), `"generation"`) {
		t.Fatalf("generation leaked: %s", detail.Body.String())
	}

	mkdir := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/workspaces/"+id+"/files/directory", `{"path":"src"}`, auth)
	if mkdir.Code != 200 {
		t.Fatalf("mkdir %d %s", mkdir.Code, mkdir.Body.String())
	}
	write := dashboardDo(t, h, http.MethodPut, "/dashboard/api/v1/workspaces/"+id+"/files/content", `{"path":"src/n.txt","content":"ok"}`, auth)
	if write.Code != 200 {
		t.Fatalf("write %d %s", write.Code, write.Body.String())
	}
	files := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+id+"/files?path=src", "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if files.Code != 200 || !strings.Contains(files.Body.String(), `"n.txt"`) {
		t.Fatalf("files %d %s", files.Code, files.Body.String())
	}
	if strings.Contains(files.Body.String(), "sha256") && strings.Contains(files.Body.String(), `"entries"`) {
		var listedFiles struct {
			Data struct {
				Entries []map[string]any `json:"entries"`
			} `json:"data"`
		}
		if err := json.Unmarshal(files.Body.Bytes(), &listedFiles); err != nil {
			t.Fatal(err)
		}
		for _, entry := range listedFiles.Data.Entries {
			if _, ok := entry["sha256"]; ok {
				t.Fatal("files_list must not project sha256")
			}
		}
	}
	read := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+id+"/files/content?path=src/n.txt", "", map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if read.Code != 200 || !strings.Contains(read.Body.String(), `"ok"`) {
		t.Fatalf("read %d %s", read.Code, read.Body.String())
	}

	stale := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/workspaces/"+id+"/close", `{"expectedGeneration":99}`, auth)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale close %d %s", stale.Code, stale.Body.String())
	}
	if strings.Contains(stale.Body.String(), "lifecycle") {
		t.Fatalf("runner text leaked: %s", stale.Body.String())
	}

	closed := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/workspaces/"+id+"/close", `{"expectedGeneration":1}`, auth)
	if closed.Code != 200 {
		t.Fatalf("close %d %s", closed.Code, closed.Body.String())
	}
}
