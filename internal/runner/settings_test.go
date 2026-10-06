package runner

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/audit"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

type failAttestor struct{ reason string }

func (f failAttestor) Verify(context.Context) (bool, string, error) { return false, f.reason, nil }

func TestDashboardSettingsPersistAndReset(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.DependencyAccess}, nil, nil)
	initial := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSettingsGet, Input: json.RawMessage(`{}`),
	})
	if !initial.OK {
		t.Fatalf("%+v", initial)
	}
	data, _ := initial.Data.(map[string]any)
	nested, _ := data["defaultNetworkProfile"].(map[string]any)
	if nested["value"] != "dependency-access" || nested["source"] != "environment" {
		t.Fatalf("%#v", nested)
	}

	updated := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSettingsUpdate,
		Input: json.RawMessage(`{"defaultNetworkProfile":"network-none"}`),
	})
	if !updated.OK {
		t.Fatalf("%+v", updated)
	}
	data, _ = updated.Data.(map[string]any)
	nested, _ = data["defaultNetworkProfile"].(map[string]any)
	if nested["value"] != "network-none" || nested["source"] != "setting" {
		t.Fatalf("%#v", nested)
	}

	reset := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSettingsUpdate,
		Input: json.RawMessage(`{"defaultNetworkProfile":null}`),
	})
	if !reset.OK {
		t.Fatalf("%+v", reset)
	}
	data, _ = reset.Data.(map[string]any)
	nested, _ = data["defaultNetworkProfile"].(map[string]any)
	if nested["value"] != "dependency-access" || nested["source"] != "environment" {
		t.Fatalf("%#v", nested)
	}

	refused := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSettingsUpdate,
		Input: json.RawMessage(`{"defaultNetworkProfile":"local-host"}`),
	})
	if refused.OK || refused.Error == nil || refused.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("%+v", refused)
	}
}

func TestDashboardSettingsAuditAndNetworkCheck(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "settings.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	aud, err := audit.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.DependencyAccess, Attestor: failAttestor{reason: "host firewall is not attested"}}, nil, nil).WithAudit(aud)
	_ = svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSettingsUpdate,
		Input: json.RawMessage(`{"defaultNetworkProfile":"network-none"}`),
	})
	_ = svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSettingsUpdate,
		Input: json.RawMessage(`{"defaultNetworkProfile":null}`),
	})
	events, err := aud.List("owner", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	changed := 0
	for _, event := range events {
		if event.Action == "settings.default_network_profile.changed" {
			changed++
			raw, _ := json.Marshal(event.Details)
			if strings.Contains(string(raw), "firewall") {
				t.Fatalf("audit leaked %s", raw)
			}
		}
	}
	if changed != 2 {
		t.Fatalf("audits %d %#v", changed, events)
	}

	check := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSettingsNetworkCheck, Input: json.RawMessage(`{}`),
	})
	if !check.OK {
		t.Fatalf("%+v", check)
	}
	data, _ := check.Data.(map[string]any)
	if data["ready"] != false || data["reason"] != "host firewall is not attested" {
		t.Fatalf("%#v", data)
	}
	ready := NewService(Config{NetworkProfile: protocol.DependencyAccess, Attestor: okAttestor{}}, nil, nil)
	ok := ready.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSettingsNetworkCheck, Input: json.RawMessage(`{}`),
	})
	if !ok.OK {
		t.Fatalf("%+v", ok)
	}
	data, _ = ok.Data.(map[string]any)
	if data["ready"] != true || data["reason"] != nil {
		t.Fatalf("%#v", data)
	}
}

func TestDashboardToolkitsListAndPreview(t *testing.T) {
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil)
	listed := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpToolkitsList, Input: json.RawMessage(`{}`),
	})
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}
	raw, _ := json.Marshal(listed.Data)
	if !strings.Contains(string(raw), `"id":"mattpocock/skills"`) || !strings.Contains(string(raw), `"kitId":"engineer"`) {
		t.Fatalf("%s", raw)
	}
	if strings.Contains(string(raw), "ak_dev_") || strings.Contains(string(raw), `"credential":`) {
		t.Fatalf("credential leaked %s", raw)
	}
	preview := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpToolkitsPreview,
		Input: json.RawMessage(`{"toolkits":[{"kind":"preset","id":"mattpocock/skills"}]}`),
	})
	if !preview.OK {
		t.Fatalf("%+v", preview)
	}
	data, _ := preview.Data.(map[string]any)
	if data["toolkitsCount"] != float64(1) && data["toolkitsCount"] != 1 {
		t.Fatalf("%#v", data)
	}
	fp, _ := data["requestFingerprint"].(string)
	if len(fp) != 64 {
		t.Fatalf("fingerprint %q", fp)
	}
	if protocol.OpToolkitsList.Known() || protocol.OpSettingsGet.Known() || !protocol.OpSettingsUpdate.Dashboard() {
		t.Fatal("settings/toolkits must stay dashboard-only")
	}
}
