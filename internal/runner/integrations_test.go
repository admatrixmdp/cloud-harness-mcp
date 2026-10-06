package runner

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/integrations"
	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func integrationsService(t *testing.T) *Service {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "integrations.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ring, err := secrets.NewKeyring(1, []secrets.KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{13}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	store, err := integrations.Open(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithIntegrations(store)
}

func TestDashboardIntegrationCredentialsWriteOnly(t *testing.T) {
	svc := integrationsService(t)
	secret := "ts_live_do_not_log_this_value"
	before := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpTypesafeStatus, Input: json.RawMessage(`{}`),
	})
	if !before.OK {
		t.Fatalf("%+v", before)
	}
	status, _ := before.Data.(map[string]any)
	if status["configured"] != false || status["enabled"] != true {
		t.Fatalf("%#v", status)
	}

	created := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpIntegrationCredentialCreate,
		Input: json.RawMessage(`{"integration":"typesafe","label":"TypeSafe","value":"` + secret + `","expectedGeneration":0}`),
	})
	if !created.OK {
		t.Fatalf("%+v", created)
	}
	raw, _ := json.Marshal(created)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), `"value"`) {
		t.Fatalf("leaked %s", raw)
	}
	data, _ := created.Data.(map[string]any)
	id, _ := data["id"].(string)

	after := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpTypesafeStatus, Input: json.RawMessage(`{}`),
	})
	afterRaw, _ := json.Marshal(after)
	if !after.OK || !strings.Contains(string(afterRaw), `"configured":true`) || strings.Contains(string(afterRaw), secret) {
		t.Fatalf("%s", afterRaw)
	}

	listed := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpIntegrationCredentialList, Input: json.RawMessage(`{}`),
	})
	listRaw, _ := json.Marshal(listed)
	if !listed.OK || strings.Contains(string(listRaw), secret) || strings.Contains(string(listRaw), `"value"`) {
		t.Fatalf("%s", listRaw)
	}

	rotated := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpIntegrationCredentialRotate,
		Input: json.RawMessage(`{"credentialId":"` + id + `","value":"ts_live_rotated","expectedGeneration":1}`),
	})
	rotRaw, _ := json.Marshal(rotated)
	if !rotated.OK || strings.Contains(string(rotRaw), "ts_live_rotated") {
		t.Fatalf("%s", rotRaw)
	}
	rotData, _ := rotated.Data.(map[string]any)
	if rotData["generation"] != float64(2) && rotData["generation"] != 2 {
		t.Fatalf("%#v", rotData)
	}

	deleted := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpIntegrationCredentialDelete,
		Input: json.RawMessage(`{"credentialId":"` + id + `","expectedGeneration":2}`),
	})
	if !deleted.OK {
		t.Fatalf("%+v", deleted)
	}

	if protocol.OpIntegrationCredentialList.Known() || protocol.OpTypesafeStatus.Known() || !protocol.OpIntegrationCredentialCreate.Dashboard() {
		t.Fatal("integration credential ops must stay dashboard-only")
	}
}

func TestDashboardIntegrationCredentialsUnavailableWithoutStore(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	got := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpIntegrationCredentialCreate,
		Input: json.RawMessage(`{"integration":"typesafe","label":"TypeSafe","value":"ts_live_key","expectedGeneration":0}`),
	})
	if got.OK || got.Error == nil || got.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("%+v", got)
	}
}

func TestSkillSuggestUsesStoredIntegrationKey(t *testing.T) {
	svc := integrationsService(t)
	created := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpIntegrationCredentialCreate,
		Input: json.RawMessage(`{"integration":"typesafe","label":"TypeSafe","value":"ts_live_key","expectedGeneration":0}`),
	})
	if !created.OK {
		t.Fatalf("%+v", created)
	}
	got := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSkillSuggest,
		Input: json.RawMessage(`{"prompt":"Please refactor the authentication middleware."}`),
	})
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	data, _ := got.Data.(map[string]any)
	if data["reason"] != "empty_roster" || data["outboundCalls"] != 0 {
		t.Fatalf("%#v", data)
	}
}
