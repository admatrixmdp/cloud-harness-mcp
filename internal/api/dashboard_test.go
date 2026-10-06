package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/artifacts"
	"github.com/bestagentkits/cloud-harness-mcp/internal/grants"
	"github.com/bestagentkits/cloud-harness-mcp/internal/knowledge"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcpgw"
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
	kn, err := knowledge.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := mcpgw.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	art, err := artifacts.Open(db, artifacts.Options{Root: filepath.Join(t.TempDir(), "objects-root")})
	if err != nil {
		t.Fatal(err)
	}
	svc := runner.NewService(runner.Config{NetworkProfile: protocol.NetworkNone, JobsRoot: t.TempDir()}, nil, nil).
		WithGrants(store).WithKnowledge(kn).WithMCPGateway(gw).WithArtifacts(art)
	inner := httptest.NewServer(runner.Handler(runner.Options{Service: svc}))
	t.Cleanup(inner.Close)
	h := Handler(Options{
		BearerToken: "owner-secret",
		OwnerID:     "owner",
		Runner:      &mcp.RunnerClient{BaseURL: inner.URL, OwnerID: "owner"},
		Security:    SecurityConfig{PublicHosts: []string{"dashboard.example"}, AllowedOrigins: []string{"https://dashboard.example"}},
		MCPGatewayResolve: func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
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

func TestDashboardMCPServersAndKnowledge(t *testing.T) {
	h, _ := dashboardFixture(t)
	csrf, cookie := dashboardCSRF(t, h)
	auth := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/mcp-servers", `{"name":"github","transport":"streamable-http","endpoint":"https://github.example.com/mcp","headers":[{"name":"Authorization","value":{"secretRef":"GITHUB_TOKEN"}}],"expectedGeneration":0}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("missing csrf status %d %s", denied.Code, denied.Body.String())
	}

	private := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/mcp-servers", `{"name":"loop","transport":"streamable-http","endpoint":"https://127.0.0.1/mcp","expectedGeneration":0}`, auth)
	if private.Code != http.StatusBadRequest || !strings.Contains(private.Body.String(), "private") {
		t.Fatalf("private endpoint %d %s", private.Code, private.Body.String())
	}

	sse := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/mcp-servers", `{"name":"sse","transport":"sse","endpoint":"https://github.example.com/mcp","headers":[{"name":"Authorization","value":{"secretRef":"GITHUB_TOKEN"}}],"expectedGeneration":0}`, auth)
	if sse.Code != http.StatusBadRequest || !strings.Contains(sse.Body.String(), "authenticated SSE") {
		t.Fatalf("authenticated sse %d %s", sse.Code, sse.Body.String())
	}

	created := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/mcp-servers", `{"name":"github","transport":"streamable-http","endpoint":"https://github.example.com/mcp","headers":[{"name":"Authorization","value":{"secretRef":"GITHUB_TOKEN"}}],"permissionDefault":"allow","enabled":true,"expectedGeneration":0}`, auth)
	if created.Code != 200 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "ghp_") || strings.Contains(created.Body.String(), `"value"`) && strings.Contains(created.Body.String(), "GITHUB_TOKEN") && strings.Contains(created.Body.String(), `"value":`) {
		if strings.Contains(created.Body.String(), `"kind":"secret"`) && strings.Contains(created.Body.String(), `"value"`) {
			t.Fatalf("secret header value leaked: %s", created.Body.String())
		}
	}
	var createdBody struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatal(err)
	}
	serverID, _ := createdBody.Data["id"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, serverID) {
		t.Fatalf("id %q body %s", serverID, created.Body.String())
	}
	if createdBody.Data["principalId"] != nil {
		t.Fatal("principalId must not reach the browser")
	}
	headers, _ := createdBody.Data["headers"].([]any)
	if len(headers) != 1 {
		t.Fatalf("headers %s", created.Body.String())
	}
	header, _ := headers[0].(map[string]any)
	if header["kind"] != "secret" || header["secretRef"] != "GITHUB_TOKEN" {
		t.Fatalf("header projection %v", header)
	}
	if _, ok := header["value"]; ok {
		t.Fatal("secret header value must not be projected")
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/mcp-servers", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), serverID) {
		t.Fatalf("list %d %s", listed.Code, listed.Body.String())
	}

	got := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/mcp-servers/"+serverID, "", map[string]string{"Authorization": "Bearer owner-secret"})
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"tools"`) {
		t.Fatalf("get %d %s", got.Code, got.Body.String())
	}

	short := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/mcp-servers/mcps_tooshort", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if short.Code != http.StatusBadRequest {
		t.Fatalf("short id %d %s", short.Code, short.Body.String())
	}

	updated := dashboardDo(t, h, http.MethodPatch, "/dashboard/api/v1/mcp-servers/"+serverID, `{"name":"github-renamed","expectedGeneration":1}`, auth)
	if updated.Code != 200 || !strings.Contains(updated.Body.String(), "github-renamed") {
		t.Fatalf("update %d %s", updated.Code, updated.Body.String())
	}

	disabled := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/mcp-servers/"+serverID+"/enabled", `{"enabled":false,"expectedGeneration":2}`, auth)
	if disabled.Code != 200 || !strings.Contains(disabled.Body.String(), `"enabled":false`) {
		t.Fatalf("enabled %d %s", disabled.Code, disabled.Body.String())
	}

	deleted := dashboardDo(t, h, http.MethodDelete, "/dashboard/api/v1/mcp-servers/"+serverID, `{"expectedGeneration":3}`, auth)
	if deleted.Code != 200 {
		t.Fatalf("delete %d %s", deleted.Code, deleted.Body.String())
	}

	item := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/knowledge", `{"kind":"memory","scope":"owner","title":"Dashboard note","content":"owner knowledge","tags":["arch"],"expectedGeneration":0}`, auth)
	if item.Code != 200 {
		t.Fatalf("knowledge create %d %s", item.Code, item.Body.String())
	}
	var itemBody struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(item.Body.Bytes(), &itemBody); err != nil {
		t.Fatal(err)
	}
	id, _ := itemBody.Data["id"].(string)
	if id == "" {
		t.Fatalf("knowledge id missing %s", item.Body.String())
	}
	if itemBody.Data["principalId"] != nil {
		t.Fatal("knowledge principalId must not reach the browser")
	}

	listedKn := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/knowledge?kind=memory", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if listedKn.Code != 200 || !strings.Contains(listedKn.Body.String(), id) {
		t.Fatalf("knowledge list %d %s", listedKn.Code, listedKn.Body.String())
	}

	read := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/knowledge/"+id, "", map[string]string{"Authorization": "Bearer owner-secret"})
	if read.Code != 200 || !strings.Contains(read.Body.String(), "owner knowledge") {
		t.Fatalf("knowledge get %d %s", read.Code, read.Body.String())
	}

	updatedKn := dashboardDo(t, h, http.MethodPut, "/dashboard/api/v1/knowledge/"+id, `{"title":"Dashboard note","content":"updated knowledge","expectedGeneration":1}`, auth)
	if updatedKn.Code != 200 || !strings.Contains(updatedKn.Body.String(), "updated knowledge") {
		t.Fatalf("knowledge update %d %s", updatedKn.Code, updatedKn.Body.String())
	}

	search := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/knowledge/search", `{"query":"updated"}`, auth)
	if search.Code != 200 || !strings.Contains(search.Body.String(), `"results"`) {
		t.Fatalf("knowledge search %d %s", search.Code, search.Body.String())
	}

	graph := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/knowledge-graph", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if graph.Code != 200 || !strings.Contains(graph.Body.String(), `"nodes"`) {
		t.Fatalf("knowledge graph %d %s", graph.Code, graph.Body.String())
	}

	staleKn := dashboardDo(t, h, http.MethodDelete, "/dashboard/api/v1/knowledge/"+id, `{"expectedGeneration":99}`, auth)
	if staleKn.Code != http.StatusConflict {
		t.Fatalf("stale knowledge delete %d %s", staleKn.Code, staleKn.Body.String())
	}

	removed := dashboardDo(t, h, http.MethodDelete, "/dashboard/api/v1/knowledge/"+id, `{"expectedGeneration":2}`, auth)
	if removed.Code != 200 || !strings.Contains(removed.Body.String(), `"deleted":true`) {
		t.Fatalf("knowledge delete %d %s", removed.Code, removed.Body.String())
	}
}

func TestDashboardArtifactsAndAgents(t *testing.T) {
	h, _ := dashboardFixture(t)
	csrf, cookie := dashboardCSRF(t, h)
	auth := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	opened := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/workspaces", `{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-art-dash-1","networkProfile":"network-none"}`, auth)
	if opened.Code != 200 {
		t.Fatalf("open %d %s", opened.Code, opened.Body.String())
	}
	var openedBody struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(opened.Body.Bytes(), &openedBody); err != nil {
		t.Fatal(err)
	}
	wsID, _ := openedBody.Data["workspaceId"].(string)
	if wsID == "" {
		t.Fatalf("open body %s", opened.Body.String())
	}

	write := dashboardDo(t, h, http.MethodPut, "/dashboard/api/v1/workspaces/"+wsID+"/files/content", `{"path":"analysis.json","content":"snapshot-bytes"}`, auth)
	if write.Code != 200 {
		t.Fatalf("write %d %s", write.Code, write.Body.String())
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/artifacts", `{"workspaceId":"`+wsID+`","path":"analysis.json","logicalName":"analysis.json","expectedGeneration":0}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	created := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/artifacts", `{"workspaceId":"`+wsID+`","path":"analysis.json","logicalName":"analysis.json","expectedGeneration":0}`, auth)
	if created.Code != 200 {
		t.Fatalf("snapshot %d %s", created.Code, created.Body.String())
	}
	var createdBody struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatal(err)
	}
	artID, _ := createdBody.Data["artifactId"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixArtifact, artID) {
		t.Fatalf("artifact id %q body %s", artID, created.Body.String())
	}
	if createdBody.Data["principalId"] != nil {
		t.Fatal("principalId must not reach the browser")
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/artifacts", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), artID) {
		t.Fatalf("list %d %s", listed.Code, listed.Body.String())
	}

	scoped := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/artifacts", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if scoped.Code != 200 || !strings.Contains(scoped.Body.String(), artID) {
		t.Fatalf("workspace artifacts %d %s", scoped.Code, scoped.Body.String())
	}

	read := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/artifacts/"+artID, "", map[string]string{"Authorization": "Bearer owner-secret"})
	if read.Code != 200 || !strings.Contains(read.Body.String(), `"content"`) {
		t.Fatalf("read %d %s", read.Code, read.Body.String())
	}

	download := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/artifacts/"+artID+"/download", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if download.Code != 200 {
		t.Fatalf("download %d %s", download.Code, download.Body.String())
	}
	if download.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("download content-type %s", download.Header().Get("Content-Type"))
	}
	if !strings.Contains(download.Header().Get("Content-Disposition"), "analysis.json") {
		t.Fatalf("disposition %s", download.Header().Get("Content-Disposition"))
	}
	if download.Body.String() != "snapshot-bytes" {
		t.Fatalf("download body %q", download.Body.String())
	}

	short := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/artifacts/art_tooshort", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if short.Code != http.StatusBadRequest {
		t.Fatalf("short artifact id %d %s", short.Code, short.Body.String())
	}

	stale := dashboardDo(t, h, http.MethodDelete, "/dashboard/api/v1/artifacts/"+artID, `{"expectedGeneration":99}`, auth)
	if stale.Code != http.StatusConflict && stale.Code != http.StatusNotFound {
		t.Fatalf("stale delete %d %s", stale.Code, stale.Body.String())
	}

	deleted := dashboardDo(t, h, http.MethodDelete, "/dashboard/api/v1/artifacts/"+artID, `{"expectedGeneration":1}`, auth)
	if deleted.Code != 200 {
		t.Fatalf("delete %d %s", deleted.Code, deleted.Body.String())
	}

	agents := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/agents", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if agents.Code != 200 || !strings.Contains(agents.Body.String(), `"agents"`) {
		t.Fatalf("agents %d %s", agents.Code, agents.Body.String())
	}

	scopedAgents := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/agents", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if scopedAgents.Code != 200 || !strings.Contains(scopedAgents.Body.String(), `"agents"`) {
		t.Fatalf("workspace agents %d %s", scopedAgents.Code, scopedAgents.Body.String())
	}

	activity := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/activity", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if activity.Code != 200 || !strings.Contains(activity.Body.String(), `"events"`) {
		t.Fatalf("activity %d %s", activity.Code, activity.Body.String())
	}

	wsActivity := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/activity", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if wsActivity.Code != 200 || !strings.Contains(wsActivity.Body.String(), `"events"`) {
		t.Fatalf("workspace activity %d %s", wsActivity.Code, wsActivity.Body.String())
	}
}
