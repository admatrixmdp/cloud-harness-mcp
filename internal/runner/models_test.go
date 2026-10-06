package runner

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/models"
	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func modelsService(t *testing.T) *Service {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "models.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ring, err := secrets.NewKeyring(1, []secrets.KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{5}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	store, err := models.Open(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithModels(store)
}

func TestDashboardModelCredentialsAndProfiles(t *testing.T) {
	svc := modelsService(t)
	created := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpModelCredentialCreate,
		Input: json.RawMessage(`{"label":"OpenAI Prod","provider":"openai","apiKey":"sk-prod-secret-12345"}`),
	})
	if !created.OK {
		t.Fatalf("%+v", created)
	}
	raw, _ := json.Marshal(created.Data)
	if bytes.Contains(raw, []byte("sk-prod-secret-12345")) || bytes.Contains(raw, []byte(`"apiKey"`)) {
		t.Fatalf("plaintext leaked %s", raw)
	}
	data, _ := created.Data.(map[string]any)
	credID, _ := data["id"].(string)
	listed := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpModelCredentialList,
		Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}
	listRaw, _ := json.Marshal(listed.Data)
	if bytes.Contains(listRaw, []byte("sk-prod-secret-12345")) {
		t.Fatalf("list leaked %s", listRaw)
	}
	profile := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpModelProfileCreate,
		Input: json.RawMessage(`{"profileId":"coding-fast","displayName":"Fast Coding","credentialId":"` + credID + `","model":"gpt-5.2-codex","apiMode":"chat-completions","pricing":{"inputMicrosPerMillionTokens":1000,"outputMicrosPerMillionTokens":2000},"limits":{"maxInputTokens":10000,"maxOutputTokens":2000,"maxCostMicros":50000},"maxProxyOperations":["files_read","grep_search"]}`),
	})
	if !profile.OK {
		t.Fatalf("%+v", profile)
	}
	refused := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpModelCredentialDelete,
		Input: json.RawMessage(`{"credentialId":"` + credID + `","expectedGeneration":1}`),
	})
	if refused.OK || refused.Error == nil || refused.Error.Code != protocol.ErrorConflict {
		t.Fatalf("referenced delete %+v", refused)
	}
	disabled := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpModelProfileDisable,
		Input: json.RawMessage(`{"profileId":"coding-fast","expectedGeneration":1}`),
	})
	if !disabled.OK {
		t.Fatalf("%+v", disabled)
	}
	status := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpModelConfigStatus,
		Input: json.RawMessage(`{}`),
	})
	if !status.OK {
		t.Fatalf("%+v", status)
	}
	statusRaw, _ := json.Marshal(status.Data)
	if !strings.Contains(string(statusRaw), `"activeCredentialCount":1`) || !strings.Contains(string(statusRaw), `"activeProfileCount":0`) {
		t.Fatalf("status %s", statusRaw)
	}
	if protocol.OpModelCredentialList.Known() || protocol.OpModelProfileCreate.Known() || !protocol.OpModelConfigStatus.Dashboard() {
		t.Fatal("model dashboard ops must stay dashboard-only")
	}
}

func TestModelOpsUnavailableWithoutStore(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	got := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpModelCredentialList,
		Input: json.RawMessage(`{}`),
	})
	if got.OK || got.Error == nil || got.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("%+v", got)
	}
}
