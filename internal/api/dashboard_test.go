package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apiembed "github.com/bestagentkits/cloud-harness-mcp/apps/api"
	"github.com/bestagentkits/cloud-harness-mcp/internal/artifacts"
	"github.com/bestagentkits/cloud-harness-mcp/internal/audit"
	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
	"github.com/bestagentkits/cloud-harness-mcp/internal/githubapp"
	"github.com/bestagentkits/cloud-harness-mcp/internal/grants"
	"github.com/bestagentkits/cloud-harness-mcp/internal/integrations"
	"github.com/bestagentkits/cloud-harness-mcp/internal/knowledge"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcpgw"
	"github.com/bestagentkits/cloud-harness-mcp/internal/metadata"
	"github.com/bestagentkits/cloud-harness-mcp/internal/models"
	"github.com/bestagentkits/cloud-harness-mcp/internal/runner"
	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/internal/skillsreg"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func dashboardFixture(t *testing.T) (http.Handler, *grants.Store) {
	t.Helper()
	h, store, _ := dashboardStores(t)
	return h, store
}

type stubGitHubVerifier struct{}

func (stubGitHubVerifier) VerifyInstallation(id string) (githubapp.Verified, error) {
	return githubapp.Verified{
		AppID: "1", InstallationID: id, AccountID: id, AccountLogin: "org-" + id, Status: "active",
		Repositories: []githubapp.VerifiedRepo{{Owner: "org-" + id, Repository: "repo", Contents: "write"}},
	}, nil
}

func dashboardStores(t *testing.T) (http.Handler, *grants.Store, *audit.Store) {
	t.Helper()
	h, store, aud, _ := dashboardGitHubStores(t)
	return h, store, aud
}

func dashboardGitHubStores(t *testing.T) (http.Handler, *grants.Store, *audit.Store, *githubapp.Store) {
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
	aud, err := audit.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	gh, err := githubapp.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := metadata.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secrets.NewKeyring(1, []secrets.KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	sec, err := secrets.OpenMetadata(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	modelStore, err := models.Open(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	skillStore, err := skillsreg.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	intStore, err := integrations.Open(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	svc := runner.NewService(runner.Config{
		NetworkProfile: protocol.NetworkNone,
		JobsRoot:       t.TempDir(),
		GitHubApp:      git.AppConfig{AppID: "1", AppSlug: "test-app"},
	}, nil, nil).
		WithGrants(store).WithKnowledge(kn).WithMCPGateway(gw).WithArtifacts(art).WithAudit(aud).
		WithGitHub(gh, stubGitHubVerifier{}).WithMetadata(meta).WithSecrets(sec).WithModels(modelStore).WithSkills(skillStore).WithIntegrations(intStore)
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
	return h, store, aud, gh
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

func TestParseGitStatusAndWorktrees(t *testing.T) {
	got := parseGitStatus("## main...origin/main [ahead 2, behind 1]\nM  staged.txt\n M dirty.txt\n?? untracked.txt\n")
	if got["branch"] != "main" || got["upstream"] != "origin/main" {
		t.Fatalf("branch %+v", got)
	}
	if got["ahead"] != 2 || got["behind"] != 1 {
		t.Fatalf("ahead/behind %+v", got)
	}
	if got["staged"] != 1 || got["modified"] != 1 || got["untracked"] != 1 {
		t.Fatalf("counts %+v", got)
	}
	trees := parseWorktrees("/tmp/repo abcdef1 [main]\n/tmp/feature defabc2 [feature]\n")
	if len(trees) != 2 || trees[0]["path"] != "/tmp/repo" || trees[1]["branch"] != "feature" {
		t.Fatalf("worktrees %+v", trees)
	}
}

func TestDashboardGitRuntimeAndAutomation(t *testing.T) {
	h, _ := dashboardFixture(t)
	csrf, cookie := dashboardCSRF(t, h)
	auth := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	opened := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/workspaces", `{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-git-dash-1","networkProfile":"network-none"}`, auth)
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

	status := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/git/status", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if status.Code != 200 {
		t.Fatalf("git status %d %s", status.Code, status.Body.String())
	}
	if !strings.Contains(status.Body.String(), `"branch"`) || !strings.Contains(status.Body.String(), `"output"`) {
		t.Fatalf("git status body %s", status.Body.String())
	}

	diff := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/git/diff", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if diff.Code != 200 {
		t.Fatalf("git diff %d %s", diff.Code, diff.Body.String())
	}

	log := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/git/log?limit=10", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if log.Code != 200 || !strings.Contains(log.Body.String(), `"commits"`) {
		t.Fatalf("git log %d %s", log.Code, log.Body.String())
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/workspaces/"+wsID+"/git/fetch", `{}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	worktrees := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/worktrees", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if worktrees.Code != 200 || !strings.Contains(worktrees.Body.String(), `"worktrees"`) {
		t.Fatalf("worktrees %d %s", worktrees.Code, worktrees.Body.String())
	}

	badName := dashboardDo(t, h, http.MethodDelete, "/dashboard/api/v1/workspaces/"+wsID+"/worktrees/bad@name", `{}`, auth)
	if badName.Code != http.StatusBadRequest {
		t.Fatalf("bad worktree name %d %s", badName.Code, badName.Body.String())
	}

	skills := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/skills", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if skills.Code != 200 || !strings.Contains(skills.Body.String(), `"skills"`) {
		t.Fatalf("skills %d %s", skills.Code, skills.Body.String())
	}

	hooks := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/hooks", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if hooks.Code != 200 || !strings.Contains(hooks.Body.String(), `"hooks"`) {
		t.Fatalf("hooks %d %s", hooks.Code, hooks.Body.String())
	}

	deployments := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/deployments", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if deployments.Code != 200 || !strings.Contains(deployments.Body.String(), `"deployments"`) {
		t.Fatalf("deployments %d %s", deployments.Code, deployments.Body.String())
	}

	graph := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/tasks/graph", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if graph.Code != 200 || !strings.Contains(graph.Body.String(), `"nodes"`) {
		t.Fatalf("tasks graph %d %s", graph.Code, graph.Body.String())
	}

	shortTask := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/workspaces/"+wsID+"/tasks/task_tooshort", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if shortTask.Code != http.StatusBadRequest {
		t.Fatalf("short task id %d %s", shortTask.Code, shortTask.Body.String())
	}

	session := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/workspaces/"+wsID+"/sessions", `{"name":"cockpit"}`, auth)
	if session.Code != 200 && session.Code != http.StatusServiceUnavailable && session.Code != http.StatusNotFound && session.Code != http.StatusBadRequest {
		t.Fatalf("sessions open %d %s", session.Code, session.Body.String())
	}
	if session.Code == 200 && strings.Contains(session.Body.String(), `"stdin"`) {
		t.Fatal("session stdin must not reach the browser")
	}
}

func TestNormalizeServerVersion(t *testing.T) {
	for _, accepted := range []string{"0.62.8", "0.39.0", "0.40.0-beta.12", "1.2.3+build.7", "1.0.0-rc.1+build.9", "1.2.3+" + strings.Repeat("a", 80)} {
		if got := apiembed.NormalizeServerVersion(accepted); got != accepted {
			t.Fatalf("accepted %q got %q", accepted, got)
		}
	}
	for _, rejected := range []string{"</script>", `0.39.0" onload="x`, "", " ", "1.0.0 ", "1.0.0/../x", "<b>"} {
		if got := apiembed.NormalizeServerVersion(rejected); got != "unknown" {
			t.Fatalf("rejected %q got %q", rejected, got)
		}
	}
	if apiembed.ServerVersion() != "0.62.8" {
		t.Fatalf("server version %s", apiembed.ServerVersion())
	}
}

func TestDashboardShellAndAssets(t *testing.T) {
	h, _ := dashboardFixture(t)
	auth := map[string]string{"Authorization": "Bearer owner-secret"}
	version := apiembed.ServerVersion()

	shell := dashboardDo(t, h, http.MethodGet, "/dashboard", "", auth)
	if shell.Code != 200 {
		t.Fatalf("shell %d %s", shell.Code, shell.Body.String())
	}
	body := shell.Body.String()
	if !strings.Contains(body, "<title>Overview | Cloud Harness</title>") {
		t.Fatal("missing title")
	}
	if strings.Contains(body, "__CH_VERSION__") || strings.Contains(body, "__CH_ASSET_VERSION__") {
		t.Fatal("placeholders leaked")
	}
	if !strings.Contains(body, "v"+version) {
		t.Fatalf("missing version %s", body[:200])
	}
	if !strings.Contains(body, "/dashboard/assets/"+version+"/dashboard.css") {
		t.Fatal("missing versioned css")
	}
	if shell.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("shell cache %s", shell.Header().Get("Cache-Control"))
	}

	dark := dashboardDo(t, h, http.MethodGet, "/dashboard/overview", "", map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        "ch-dashboard-theme=dark",
	})
	if dark.Code != http.StatusFound || dark.Header().Get("Location") != "/dashboard" {
		t.Fatalf("overview redirect %d %s", dark.Code, dark.Header().Get("Location"))
	}

	themed := dashboardDo(t, h, http.MethodGet, "/dashboard/workspaces", "", map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        "ch-dashboard-theme=dark",
	})
	if !strings.Contains(themed.Body.String(), `<html lang="en" data-theme="dark">`) {
		t.Fatalf("theme %s", themed.Body.String()[:80])
	}
	ignored := dashboardDo(t, h, http.MethodGet, "/dashboard/workspaces", "", map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        "ch-dashboard-theme=neon",
	})
	if !strings.Contains(ignored.Body.String(), `<html lang="en">`) || strings.Contains(ignored.Body.String(), `data-theme="`) {
		t.Fatalf("invalid theme %s", ignored.Body.String()[:80])
	}

	github := dashboardDo(t, h, http.MethodGet, "/dashboard/github", "", auth)
	if github.Code != http.StatusFound || github.Header().Get("Location") != "/dashboard/integrations/github" {
		t.Fatalf("github redirect %d %s", github.Code, github.Header().Get("Location"))
	}
	mcpServers := dashboardDo(t, h, http.MethodGet, "/dashboard/integrations/mcp-servers", "", auth)
	if mcpServers.Code != http.StatusFound || mcpServers.Header().Get("Location") != "/dashboard/mcp-servers" {
		t.Fatalf("mcp redirect %d %s", mcpServers.Code, mcpServers.Header().Get("Location"))
	}

	asset := dashboardDo(t, h, http.MethodGet, "/dashboard/assets/"+version+"/dashboard-pages.js", "", auth)
	if asset.Code != 200 {
		t.Fatalf("asset %d %s", asset.Code, asset.Body.String())
	}
	if !strings.Contains(asset.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("content-type %s", asset.Header().Get("Content-Type"))
	}
	if asset.Header().Get("Cache-Control") != "private, max-age=31536000, immutable" {
		t.Fatalf("asset cache %s", asset.Header().Get("Cache-Control"))
	}
	if !strings.Contains(asset.Body.String(), "DASHBOARD_PAGES") {
		t.Fatal("pages missing")
	}

	legacy := dashboardDo(t, h, http.MethodGet, "/dashboard/assets/dashboard-pages.js", "", auth)
	if legacy.Code != 200 || legacy.Header().Get("Cache-Control") != "private, no-cache" {
		t.Fatalf("legacy %d %s", legacy.Code, legacy.Header().Get("Cache-Control"))
	}

	wrong := dashboardDo(t, h, http.MethodGet, "/dashboard/assets/not-"+version+"/dashboard-pages.js", "", auth)
	if wrong.Code != 404 {
		t.Fatalf("wrong version %d", wrong.Code)
	}
	secret := dashboardDo(t, h, http.MethodGet, "/dashboard/assets/"+version+"/package.json", "", auth)
	if secret.Code != 404 {
		t.Fatalf("package.json %d", secret.Code)
	}

	nested := dashboardDo(t, h, http.MethodGet, "/dashboard/workspaces/ws_abcdefghijklmnopqrstuvwx/git", "", auth)
	if nested.Code != 200 || !strings.Contains(nested.Body.String(), "<title>Overview | Cloud Harness</title>") {
		t.Fatalf("nested shell %d", nested.Code)
	}
}

func TestDashboardProfileAndPreferences(t *testing.T) {
	h, _ := dashboardFixture(t)
	csrf, cookie := dashboardCSRF(t, h)
	auth := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	profile := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/profile", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if profile.Code != 200 {
		t.Fatalf("profile %d %s", profile.Code, profile.Body.String())
	}
	if !strings.Contains(profile.Body.String(), `"preferences"`) || strings.Contains(profile.Body.String(), "owner-secret") {
		t.Fatalf("profile body %s", profile.Body.String())
	}

	server := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/server", "", map[string]string{"Authorization": "Bearer owner-secret"})
	if server.Code != 200 || !strings.Contains(server.Body.String(), `"version":"`+apiembed.ServerVersion()+`"`) {
		t.Fatalf("server %d %s", server.Code, server.Body.String())
	}

	denied := dashboardDo(t, h, http.MethodPut, "/dashboard/api/v1/preferences", `{"theme":"dark"}`, map[string]string{"Authorization": "Bearer owner-secret"})
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	ok := dashboardDo(t, h, http.MethodPut, "/dashboard/api/v1/preferences", `{"theme":"dark","displayName":"Ada"}`, auth)
	if ok.Code != 200 {
		t.Fatalf("preferences %d %s", ok.Code, ok.Body.String())
	}
	setCookie := strings.Join(ok.Result().Header.Values("Set-Cookie"), "\n")
	if !strings.Contains(setCookie, "ch-dashboard-theme=dark") || !strings.Contains(setCookie, "HttpOnly") || !strings.Contains(setCookie, "Secure") {
		t.Fatalf("set-cookie %s", setCookie)
	}
	if !strings.Contains(ok.Body.String(), `"theme":"dark"`) || !strings.Contains(ok.Body.String(), `"displayName":"Ada"`) {
		t.Fatalf("pref body %s", ok.Body.String())
	}

	badName := dashboardDo(t, h, http.MethodPut, "/dashboard/api/v1/preferences", `{"displayName":"<script>"}`, auth)
	if badName.Code != http.StatusBadRequest {
		t.Fatalf("bad name %d %s", badName.Code, badName.Body.String())
	}
}

func TestOverviewMetricsReliabilityProjections(t *testing.T) {
	now := time.Date(2026, 8, 17, 1, 0, 0, 0, time.UTC).UnixMilli()
	ws := func(id, status string, expiresMinutes int) map[string]any {
		return map[string]any{
			"workspaceId": id, "status": status,
			"expiresAt": time.UnixMilli(now + int64(expiresMinutes)*60_000).UTC().Format(time.RFC3339Nano),
		}
	}
	agent := func(id, status string, cost int64, startedMinutesAgo int) map[string]any {
		return map[string]any{
			"agentId": id, "status": status, "usage": map[string]any{"costMicros": cost},
			"startedAt": time.UnixMilli(now - int64(startedMinutesAgo)*60_000).UTC().Format(time.RFC3339Nano),
		}
	}

	projection := buildOverviewProjection(
		[]map[string]any{
			ws("ws_"+strings.Repeat("c", 24), "FAILED", 120),
			ws("ws_"+strings.Repeat("d", 24), "NETWORK_QUARANTINED", 120),
			ws("ws_"+strings.Repeat("e", 24), "ACTIVE", 5),
			ws("ws_"+strings.Repeat("f", 24), "ACTIVE", 600),
		},
		[]map[string]any{
			agent("agent_"+strings.Repeat("g", 24), "FAILED", 0, 1),
			agent("agent_"+strings.Repeat("h", 24), "LIMIT_EXCEEDED", 0, 1),
			agent("agent_"+strings.Repeat("i", 24), "RUNNING", 250_000, 1),
		},
		[]map[string]any{{"id": "grant_1"}, {"id": "grant_2"}},
		now,
	)
	ids := make([]string, 0)
	for _, item := range asObjectList(projection["attention"]) {
		ids = append(ids, str(item["id"]))
		if !strings.HasPrefix(str(item["href"]), "/dashboard") {
			t.Fatalf("href %v", item["href"])
		}
	}
	joined := strings.Join(ids, ",")
	for _, want := range []string{
		"workspace-failed-ws_" + strings.Repeat("c", 24),
		"workspace-quarantined-ws_" + strings.Repeat("d", 24),
		"workspace-expiring-ws_" + strings.Repeat("e", 24),
		"agent-agent_" + strings.Repeat("g", 24),
		"pending-approvals",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
	if strings.Contains(joined, "ws_"+strings.Repeat("f", 24)) || strings.Contains(joined, "agent_"+strings.Repeat("i", 24)) {
		t.Fatalf("healthy rows in attention %s", joined)
	}

	costed := buildOverviewProjection(
		[]map[string]any{ws("ws_"+strings.Repeat("a", 24), "ACTIVE", 120), ws("ws_"+strings.Repeat("c", 24), "CLOSED", 120)},
		[]map[string]any{
			agent("agent_"+strings.Repeat("b", 24), "RUNNING", 1_000_000, 1),
			agent("agent_"+strings.Repeat("j", 24), "SUCCEEDED", 9_000_000, 1),
		},
		nil, now,
	)
	running, _ := costed["running"].(map[string]any)
	if running["agents"] != 1 || running["workspaces"] != 1 {
		t.Fatalf("running %+v", running)
	}
	cost, _ := costed["cost"].(map[string]any)
	if cost["scope"] != "running agents" || numberInt64(cost["costMicros"]) != 1_000_000 || cost["agentCount"] != 1 {
		t.Fatalf("cost %+v", cost)
	}

	empty := buildOverviewProjection(nil, nil, nil, now)
	if len(asObjectList(empty["attention"])) != 0 {
		t.Fatal("empty attention")
	}
	if empty["agentSeriesScope"] != "no agents on record" {
		t.Fatalf("scope %v", empty["agentSeriesScope"])
	}

	events := []map[string]any{
		{"action": "workspace_open", "subjectType": "workspace", "createdAt": time.UnixMilli(now - 30*60_000).UTC().Format(time.RFC3339Nano)},
		{"action": "workspace_close", "subjectType": "workspace", "createdAt": time.UnixMilli(now - 3*3_600_000).UTC().Format(time.RFC3339Nano)},
		{"action": "skill_import_start", "subjectType": "skill", "createdAt": time.UnixMilli(now - 6*86_400_000).UTC().Format(time.RFC3339Nano)},
	}
	hour := buildMetricsProjection(events, "1h", now, 12)
	if hour["eventCount"] != 1 {
		t.Fatalf("hour count %v", hour["eventCount"])
	}
	cats, _ := hour["categories"].(map[string]int)
	if cats["workspace"] != 1 {
		t.Fatalf("hour cats %+v", cats)
	}
	week := buildMetricsProjection(events, "7d", now, 12)
	if week["eventCount"] != 3 {
		t.Fatalf("week count %v", week["eventCount"])
	}

	traces := []map[string]any{
		{"serverId": "mcps_a", "serverName": "linear", "durationMs": 10, "status": "ok"},
		{"serverId": "mcps_a", "serverName": "linear", "durationMs": 20, "status": "ok"},
		{"serverId": "mcps_a", "serverName": "linear", "durationMs": 30, "status": "error", "errorCode": "TIMEOUT"},
		{"serverId": "mcps_a", "serverName": "linear", "durationMs": 40, "status": "ok"},
		{"serverId": "mcps_a", "serverName": "linear", "durationMs": 50, "status": "ok"},
		{"serverId": "mcps_b", "serverName": "jira", "durationMs": 5, "status": "ok"},
	}
	rel := buildReliabilityProjection(traces)
	if rel["totalCalls"] != 6 {
		t.Fatalf("calls %v", rel["totalCalls"])
	}
	var linear map[string]any
	for _, row := range asObjectList(rel["servers"]) {
		if str(row["serverId"]) == "mcps_a" {
			linear = row
		}
	}
	if linear["success"] != 4 || linear["error"] != 1 || linear["calls"] != 5 || linear["p50Ms"] != 30.0 || linear["p95Ms"] != 50.0 {
		t.Fatalf("linear %+v", linear)
	}
	emptyRel := buildReliabilityProjection(nil)
	if emptyRel["totalCalls"] != 0 || len(asObjectList(emptyRel["servers"])) != 0 {
		t.Fatalf("empty rel %+v", emptyRel)
	}
}

func TestDashboardOverviewMetricsAudit(t *testing.T) {
	h, store, aud := dashboardStores(t)
	if _, err := store.Create("owner", "ws_abcdefghijklmnopqrstuvwx", grants.SkillGrantCommand("tdd", "run.sh", "aa"), ".", 60_000); err != nil {
		t.Fatal(err)
	}
	if _, err := aud.Record("owner", "workspace_open", "workspace", "ws_abcdefghijklmnopqrstuvwx", 1, map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	auth := map[string]string{"Authorization": "Bearer owner-secret"}

	overview := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/overview", "", auth)
	if overview.Code != 200 {
		t.Fatalf("overview %d %s", overview.Code, overview.Body.String())
	}
	if !strings.Contains(overview.Body.String(), `"pending-approvals"`) || strings.Contains(overview.Body.String(), "owner-secret") {
		t.Fatalf("overview body %s", overview.Body.String())
	}

	metrics := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/metrics?window=24h", "", auth)
	if metrics.Code != 200 || !strings.Contains(metrics.Body.String(), `"eventCount":1`) {
		t.Fatalf("metrics %d %s", metrics.Code, metrics.Body.String())
	}
	badWindow := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/metrics?window=30d", "", auth)
	if badWindow.Code != http.StatusBadRequest {
		t.Fatalf("window %d %s", badWindow.Code, badWindow.Body.String())
	}

	auditList := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/audit?limit=50", "", auth)
	if auditList.Code != 200 || !strings.Contains(auditList.Body.String(), `"workspace_open"`) {
		t.Fatalf("audit %d %s", auditList.Code, auditList.Body.String())
	}

	activity := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/activity", "", auth)
	if activity.Code != 200 || !strings.Contains(activity.Body.String(), `"durable":true`) {
		t.Fatalf("activity %d %s", activity.Code, activity.Body.String())
	}

	reliability := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/reliability", "", auth)
	if reliability.Code != 200 || !strings.Contains(reliability.Body.String(), `"totalCalls":0`) {
		t.Fatalf("reliability %d %s", reliability.Code, reliability.Body.String())
	}

	if protocol.OpAuditList.Known() || !protocol.OpAuditList.Dashboard() {
		t.Fatal("audit_list must stay dashboard-only")
	}
}

func TestDashboardGitHubStatusSetupDisconnect(t *testing.T) {
	h, _, _, gh := dashboardGitHubStores(t)
	if _, err := gh.ReplaceVerified("owner", githubapp.Verified{
		AppID: "1", InstallationID: "101", AccountID: "201", AccountLogin: "org-one", Status: "active",
		Repositories: []githubapp.VerifiedRepo{{Owner: "org-one", Repository: "repo1", Contents: "write"}},
	}, 100); err != nil {
		t.Fatal(err)
	}
	auth := map[string]string{"Authorization": "Bearer owner-secret"}
	status := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/github", "", auth)
	if status.Code != 200 {
		t.Fatalf("status %d %s", status.Code, status.Body.String())
	}
	body := status.Body.String()
	if !strings.Contains(body, `"installationId":"101"`) || !strings.Contains(body, `"configured":true`) {
		t.Fatalf("status body %s", body)
	}
	if strings.Contains(body, `"ownerId"`) || strings.Contains(body, `"secretToken"`) || strings.Contains(body, "owner-secret") {
		t.Fatalf("leaked %s", body)
	}

	csrf, cookie := dashboardCSRF(t, h)
	mut := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}
	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/github/setup", `{}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized && denied.Code != http.StatusForbidden {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	setup := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/github/setup", `{}`, mut)
	if setup.Code != 200 {
		t.Fatalf("setup %d %s", setup.Code, setup.Body.String())
	}
	if !strings.Contains(setup.Body.String(), `"url":"https://github.com/apps/test-app/installations/new?state=`) {
		t.Fatalf("setup body %s", setup.Body.String())
	}
	var setupBody struct {
		Data struct {
			State string `json:"state"`
			URL   string `json:"url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupBody); err != nil || setupBody.Data.State == "" {
		t.Fatalf("setup parse %s", setup.Body.String())
	}
	complete := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/github/complete", `{"state":"`+setupBody.Data.State+`","installationId":"456"}`, mut)
	if complete.Code != 200 || !strings.Contains(complete.Body.String(), `"installationId":"456"`) {
		t.Fatalf("complete %d %s", complete.Code, complete.Body.String())
	}

	disconnect := dashboardDo(t, h, http.MethodDelete, "/dashboard/api/v1/github/installations/101", `{}`, mut)
	if disconnect.Code != 200 {
		t.Fatalf("disconnect %d %s", disconnect.Code, disconnect.Body.String())
	}
	var disconnectBody struct {
		Data struct {
			Installations []map[string]any `json:"installations"`
		} `json:"data"`
	}
	if err := json.Unmarshal(disconnect.Body.Bytes(), &disconnectBody); err != nil {
		t.Fatalf("disconnect parse %s", disconnect.Body.String())
	}
	for _, row := range disconnectBody.Data.Installations {
		if fmt.Sprint(row["installationId"]) == "101" {
			t.Fatalf("disconnected installation still listed %s", disconnect.Body.String())
		}
	}

	if protocol.OpGitHubStatus.Known() || !protocol.OpGitHubStatus.Dashboard() {
		t.Fatal("github_status must stay dashboard-only")
	}
}

func TestDashboardGitHubErrorWording(t *testing.T) {
	if dashboardMessageFor(protocol.OpGitHubReconcile, protocol.ErrorUnavailable) != githubUnavailable {
		t.Fatal("github UNAVAILABLE must not use workspace wording")
	}
	if dashboardMessageFor(protocol.OpWorkspaceStatus, protocol.ErrorUnavailable) != "The workspace service is temporarily unavailable." {
		t.Fatal("workspace UNAVAILABLE wording changed")
	}
	if dashboardMessageFor(protocol.OpGitHubSetupComplete, protocol.ErrorInvalidInput) != "The GitHub App connection could not be completed. Start the connection again." {
		t.Fatal("setup complete INVALID_INPUT wording")
	}
	if dashboardMessageFor(protocol.OpGitHubDisconnect, protocol.ErrorNotFound) != "GitHub installation not found." {
		t.Fatal("disconnect NOT_FOUND wording")
	}
	rec := httptest.NewRecorder()
	writeDashboardFailOp(rec, protocol.OpGitHubReconcile, protocol.Fail(protocol.ErrorUnavailable, "GitHub App authentication failed: Cannot read properties of undefined (reading 'appId')", true))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), githubUnavailable) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "appId") {
		t.Fatalf("runner text leaked %s", rec.Body.String())
	}
}

func TestDashboardProjectsEnvironmentsSecrets(t *testing.T) {
	h, _, _, _ := dashboardGitHubStores(t)
	auth := map[string]string{"Authorization": "Bearer owner-secret"}
	csrf, cookie := dashboardCSRF(t, h)
	mut := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/projects", `{"name":"Harness","expectedGeneration":0}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized && denied.Code != http.StatusForbidden {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	created := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/projects", `{"name":"Harness","expectedGeneration":0}`, mut)
	if created.Code != 200 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	var createdBody struct {
		Data struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Generation int    `json:"generation"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil || createdBody.Data.ID == "" {
		t.Fatalf("create parse %s", created.Body.String())
	}
	if strings.Contains(created.Body.String(), "owner-secret") {
		t.Fatal("bearer leaked")
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/projects", "", auth)
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), `"name":"Harness"`) {
		t.Fatalf("list %d %s", listed.Code, listed.Body.String())
	}

	env := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/projects/"+createdBody.Data.ID+"/environments", `{"name":"prod","expectedGeneration":0}`, mut)
	if env.Code != 200 {
		t.Fatalf("env %d %s", env.Code, env.Body.String())
	}
	var envBody struct {
		Data struct {
			ID        string `json:"id"`
			ProjectID string `json:"projectId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(env.Body.Bytes(), &envBody); err != nil || envBody.Data.ID == "" {
		t.Fatalf("env parse %s", env.Body.String())
	}

	secret := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/environments/"+envBody.Data.ID+"/secrets", `{"name":"API_TOKEN","value":"super-secret-value","description":"stripe","expectedGeneration":0}`, mut)
	if secret.Code != 200 {
		t.Fatalf("secret %d %s", secret.Code, secret.Body.String())
	}
	if strings.Contains(secret.Body.String(), "super-secret-value") || strings.Contains(secret.Body.String(), `"value"`) {
		t.Fatalf("plaintext leaked %s", secret.Body.String())
	}

	secretsList := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/environments/"+envBody.Data.ID+"/secrets", "", auth)
	if secretsList.Code != 200 || !strings.Contains(secretsList.Body.String(), `"name":"API_TOKEN"`) || !strings.Contains(secretsList.Body.String(), `"ready":true`) {
		t.Fatalf("secrets list %d %s", secretsList.Code, secretsList.Body.String())
	}
	if strings.Contains(secretsList.Body.String(), "super-secret-value") || strings.Contains(secretsList.Body.String(), `"value":`) {
		t.Fatalf("list leaked %s", secretsList.Body.String())
	}

	global := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/secrets", `{"name":"GLOBAL_TOKEN","value":"global-secret-value","expectedGeneration":0}`, mut)
	if global.Code != 200 || strings.Contains(global.Body.String(), "global-secret-value") {
		t.Fatalf("global %d %s", global.Code, global.Body.String())
	}

	if protocol.OpProjectList.Known() || protocol.OpSecretCreate.Known() || !protocol.OpProjectList.Dashboard() {
		t.Fatal("project/secret dashboard ops must stay dashboard-only")
	}
}

func TestDashboardModelCredentialsAndProfiles(t *testing.T) {
	h, _, _, _ := dashboardGitHubStores(t)
	auth := map[string]string{"Authorization": "Bearer owner-secret"}
	csrf, cookie := dashboardCSRF(t, h)
	mut := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/provider-credentials", `{"label":"OpenAI Prod","provider":"openai","apiKey":"sk-prod-secret-12345"}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized && denied.Code != http.StatusForbidden {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	created := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/provider-credentials", `{"label":"OpenAI Prod","provider":"openai","apiKey":"sk-prod-secret-12345"}`, mut)
	if created.Code != 200 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "sk-prod-secret-12345") || strings.Contains(created.Body.String(), `"apiKey"`) {
		t.Fatalf("plaintext leaked %s", created.Body.String())
	}
	var createdBody struct {
		Data struct {
			ID       string `json:"id"`
			Label    string `json:"label"`
			Provider string `json:"provider"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil || createdBody.Data.ID == "" {
		t.Fatalf("create parse %s", created.Body.String())
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/provider-credentials", "", auth)
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), `"label":"OpenAI Prod"`) {
		t.Fatalf("list %d %s", listed.Code, listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), "sk-prod-secret-12345") || strings.Contains(listed.Body.String(), `"apiKey"`) {
		t.Fatalf("list leaked %s", listed.Body.String())
	}

	profile := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/agent-model-profiles", `{"profileId":"coding-fast","displayName":"Fast Coding","credentialId":"`+createdBody.Data.ID+`","model":"gpt-5.2-codex","apiMode":"chat-completions","pricing":{"inputMicrosPerMillionTokens":1000,"outputMicrosPerMillionTokens":2000},"limits":{"maxInputTokens":10000,"maxOutputTokens":2000,"maxCostMicros":50000},"maxProxyOperations":["files_read","grep_search"]}`, mut)
	if profile.Code != 200 {
		t.Fatalf("profile %d %s", profile.Code, profile.Body.String())
	}
	if strings.Contains(profile.Body.String(), "sk-prod-secret-12345") {
		t.Fatalf("profile leaked %s", profile.Body.String())
	}

	profiles := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/agent-model-profiles", "", auth)
	if profiles.Code != 200 || !strings.Contains(profiles.Body.String(), `"displayName":"Fast Coding"`) {
		t.Fatalf("profiles %d %s", profiles.Code, profiles.Body.String())
	}

	status := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/agent-model-config-status", "", auth)
	if status.Code != 200 || !strings.Contains(status.Body.String(), `"activeCredentialCount":1`) {
		t.Fatalf("status %d %s", status.Code, status.Body.String())
	}

	if protocol.OpModelCredentialList.Known() || protocol.OpModelProfileCreate.Known() || !protocol.OpModelConfigStatus.Dashboard() {
		t.Fatal("model dashboard ops must stay dashboard-only")
	}
}

func TestDashboardSkillsRegistry(t *testing.T) {
	h, _, _, _ := dashboardGitHubStores(t)
	auth := map[string]string{"Authorization": "Bearer owner-secret"}
	csrf, cookie := dashboardCSRF(t, h)
	mut := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/skills", `{"slug":"tdd","displayName":"TDD","instructions":"# TDD\nWrite the test first.","expectedGeneration":0}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized && denied.Code != http.StatusForbidden {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	created := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/skills", `{"slug":"tdd","displayName":"TDD","instructions":"# TDD\nWrite the test first.","expectedGeneration":0}`, mut)
	if created.Code != 200 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "owner-secret") || strings.Contains(created.Body.String(), `"instructions"`) {
		t.Fatalf("leaked %s", created.Body.String())
	}
	var createdBody struct {
		Data struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil || createdBody.Data.ID == "" {
		t.Fatalf("create parse %s", created.Body.String())
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/skills", "", auth)
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), `"slug":"tdd"`) {
		t.Fatalf("list %d %s", listed.Code, listed.Body.String())
	}

	got := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/skills/"+createdBody.Data.ID, "", auth)
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"displayName":"TDD"`) {
		t.Fatalf("get %d %s", got.Code, got.Body.String())
	}

	search := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/skills/search?query=tdd", "", auth)
	if search.Code != 200 || !strings.Contains(search.Body.String(), `"slug":"tdd"`) {
		t.Fatalf("search %d %s", search.Code, search.Body.String())
	}

	set := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/skill-sets", `{"name":"core","expectedGeneration":0}`, mut)
	if set.Code != 200 {
		t.Fatalf("set %d %s", set.Code, set.Body.String())
	}

	if protocol.OpSkillList.Known() || protocol.OpSkillCreateCustom.Known() || !protocol.OpSkillSetList.Dashboard() {
		t.Fatal("skill dashboard ops must stay dashboard-only")
	}
}

func TestDashboardSettingsAndToolkits(t *testing.T) {
	h, _, _, _ := dashboardGitHubStores(t)
	auth := map[string]string{"Authorization": "Bearer owner-secret"}
	csrf, cookie := dashboardCSRF(t, h)
	mut := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	read := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/settings", "", auth)
	if read.Code != 200 || !strings.Contains(read.Body.String(), `"source":"environment"`) {
		t.Fatalf("get %d %s", read.Code, read.Body.String())
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/settings", `{"defaultNetworkProfile":"network-none"}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized && denied.Code != http.StatusForbidden {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	saved := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/settings", `{"defaultNetworkProfile":"network-none"}`, mut)
	if saved.Code != 200 || !strings.Contains(saved.Body.String(), `"source":"setting"`) {
		t.Fatalf("save %d %s", saved.Code, saved.Body.String())
	}

	reset := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/settings", `{"defaultNetworkProfile":null}`, mut)
	if reset.Code != 200 || !strings.Contains(reset.Body.String(), `"source":"environment"`) {
		t.Fatalf("reset %d %s", reset.Code, reset.Body.String())
	}

	rejected := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/settings", `{"defaultNetworkProfile":"local-host"}`, mut)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("local-host %d %s", rejected.Code, rejected.Body.String())
	}

	checked := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/settings/network-check", `{}`, mut)
	if checked.Code != 200 || !strings.Contains(checked.Body.String(), `"ready":false`) {
		t.Fatalf("check %d %s", checked.Code, checked.Body.String())
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/toolkits", "", auth)
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), `"id":"mattpocock/skills"`) || strings.Contains(listed.Body.String(), `"credential":`) {
		t.Fatalf("toolkits %d %s", listed.Code, listed.Body.String())
	}

	preview := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/toolkits/preview", `{"toolkits":[{"kind":"preset","id":"mattpocock/skills"}]}`, mut)
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), `"requestFingerprint"`) {
		t.Fatalf("preview %d %s", preview.Code, preview.Body.String())
	}

	if protocol.OpSettingsGet.Known() || protocol.OpToolkitsList.Known() || !protocol.OpSettingsUpdate.Dashboard() {
		t.Fatal("settings/toolkits dashboard ops must stay dashboard-only")
	}
}

func TestDashboardToolkitRegistry(t *testing.T) {
	h, _, _, _ := dashboardGitHubStores(t)
	auth := map[string]string{"Authorization": "Bearer owner-secret"}
	csrf, cookie := dashboardCSRF(t, h)
	mut := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/toolkit-registry", "", auth)
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), `"entries"`) || !strings.Contains(listed.Body.String(), `"presets"`) {
		t.Fatalf("list %d %s", listed.Code, listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), `"ownerId"`) {
		t.Fatalf("leaked %s", listed.Body.String())
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/toolkit-registry", `{"provider":"skills-sh","slug":"anthropics/skills/pdf","action":"install","expectedGeneration":0}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized && denied.Code != http.StatusForbidden {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	updated := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/toolkit-registry", `{"provider":"skills-sh","slug":"anthropics/skills/pdf","action":"install","expectedGeneration":0}`, mut)
	if updated.Code != 200 || !strings.Contains(updated.Body.String(), `"action":"install"`) {
		t.Fatalf("update %d %s", updated.Code, updated.Body.String())
	}

	refreshed := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/toolkit-registry/refresh", `{"provider":"skills-sh"}`, mut)
	if refreshed.Code != 200 || !strings.Contains(refreshed.Body.String(), `"slug":"anthropics/skills/pdf"`) {
		t.Fatalf("refresh %d %s", refreshed.Code, refreshed.Body.String())
	}

	if protocol.OpToolkitRegistryList.Known() || protocol.OpToolkitRegistryUpdate.Known() || !protocol.OpToolkitRegistryRefresh.Dashboard() {
		t.Fatal("toolkit_registry_* must stay dashboard-only")
	}
}

func TestDashboardIntegrationCredentials(t *testing.T) {
	h, _, _, _ := dashboardGitHubStores(t)
	auth := map[string]string{"Authorization": "Bearer owner-secret"}
	csrf, cookie := dashboardCSRF(t, h)
	mut := map[string]string{
		"Authorization": "Bearer owner-secret",
		"Cookie":        cookie,
		"x-csrf-token":  csrf,
	}
	secret := "ts_live_do_not_log_this_value"

	status := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/typesafe", "", auth)
	if status.Code != 200 || !strings.Contains(status.Body.String(), `"configured":false`) {
		t.Fatalf("status %d %s", status.Code, status.Body.String())
	}

	denied := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/integration-credentials", `{"integration":"typesafe","label":"TypeSafe","value":"`+secret+`","expectedGeneration":0}`, map[string]string{
		"Authorization": "Bearer owner-secret",
	})
	if denied.Code != http.StatusUnauthorized && denied.Code != http.StatusForbidden {
		t.Fatalf("missing csrf %d %s", denied.Code, denied.Body.String())
	}

	created := dashboardDo(t, h, http.MethodPost, "/dashboard/api/v1/integration-credentials", `{"integration":"typesafe","label":"TypeSafe","value":"`+secret+`","expectedGeneration":0}`, mut)
	if created.Code != 200 || strings.Contains(created.Body.String(), secret) || strings.Contains(created.Body.String(), `"value"`) {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	var envelope struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &envelope); err != nil || envelope.Data.ID == "" {
		t.Fatalf("id %v %s", err, created.Body.String())
	}

	listed := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/integration-credentials", "", auth)
	if listed.Code != 200 || strings.Contains(listed.Body.String(), secret) || !strings.Contains(listed.Body.String(), `"integration":"typesafe"`) {
		t.Fatalf("list %d %s", listed.Code, listed.Body.String())
	}

	after := dashboardDo(t, h, http.MethodGet, "/dashboard/api/v1/typesafe", "", auth)
	if after.Code != 200 || !strings.Contains(after.Body.String(), `"configured":true`) || strings.Contains(after.Body.String(), secret) {
		t.Fatalf("after %d %s", after.Code, after.Body.String())
	}

	rotated := dashboardDo(t, h, http.MethodPut, "/dashboard/api/v1/integration-credentials/"+envelope.Data.ID+"/rotate", `{"value":"ts_live_rotated","expectedGeneration":1}`, mut)
	if rotated.Code != 200 || strings.Contains(rotated.Body.String(), "ts_live_rotated") {
		t.Fatalf("rotate %d %s", rotated.Code, rotated.Body.String())
	}

	deleted := dashboardDo(t, h, http.MethodDelete, "/dashboard/api/v1/integration-credentials/"+envelope.Data.ID, `{"expectedGeneration":2}`, mut)
	if deleted.Code != 200 || !strings.Contains(deleted.Body.String(), `"deleted":true`) {
		t.Fatalf("delete %d %s", deleted.Code, deleted.Body.String())
	}

	if protocol.OpIntegrationCredentialList.Known() || protocol.OpTypesafeStatus.Known() || !protocol.OpIntegrationCredentialCreate.Dashboard() {
		t.Fatal("integration credential ops must stay dashboard-only")
	}
}
