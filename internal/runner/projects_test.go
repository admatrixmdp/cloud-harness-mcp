package runner

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/audit"
	"github.com/bestagentkits/cloud-harness-mcp/internal/metadata"
	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func projectsService(t *testing.T) (*Service, *audit.Store) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "projects.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	meta, err := metadata.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	aud, err := audit.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secrets.NewKeyring(1, []secrets.KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{9}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	sec, err := secrets.OpenMetadata(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).
		WithAudit(aud).WithMetadata(meta).WithSecrets(sec)
	return svc, aud
}

func TestDashboardProjectsEnvironmentsSecrets(t *testing.T) {
	svc, aud := projectsService(t)
	created := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpProjectCreate,
		Input: json.RawMessage(`{"name":"Harness","expectedGeneration":0}`),
	})
	if !created.OK {
		t.Fatalf("%+v", created)
	}
	data, _ := created.Data.(map[string]any)
	projectID, _ := data["id"].(string)
	if !protocol.ValidOpaqueID(protocol.PrefixProject, projectID) {
		t.Fatalf("%s", projectID)
	}
	env := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpEnvironmentCreate,
		Input: json.RawMessage(`{"projectId":"` + projectID + `","name":"prod","expectedGeneration":0}`),
	})
	if !env.OK {
		t.Fatalf("%+v", env)
	}
	envData, _ := env.Data.(map[string]any)
	envID, _ := envData["id"].(string)
	secret := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSecretCreate,
		Input: json.RawMessage(`{"environmentId":"` + envID + `","name":"API_TOKEN","value":"super-secret-value","description":"stripe","expectedGeneration":0}`),
	})
	if !secret.OK {
		t.Fatalf("%+v", secret)
	}
	raw, _ := json.Marshal(secret.Data)
	if bytes.Contains(raw, []byte("super-secret-value")) || bytes.Contains(raw, []byte(`"value"`)) {
		t.Fatalf("plaintext leaked %s", raw)
	}
	listed := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSecretList,
		Input: json.RawMessage(`{"environmentId":"` + envID + `"}`),
	})
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}
	listRaw, _ := json.Marshal(listed.Data)
	if bytes.Contains(listRaw, []byte("super-secret-value")) || !bytes.Contains(listRaw, []byte(`"ready":true`)) {
		t.Fatalf("list %s", listRaw)
	}
	stale := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpProjectDelete,
		Input: json.RawMessage(`{"projectId":"` + projectID + `","expectedGeneration":99}`),
	})
	if stale.OK || stale.Error == nil || stale.Error.Code != protocol.ErrorConflict {
		t.Fatalf("stale %+v", stale)
	}
	deleted := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpProjectDelete,
		Input: json.RawMessage(`{"projectId":"` + projectID + `","expectedGeneration":1}`),
	})
	if !deleted.OK {
		t.Fatalf("%+v", deleted)
	}
	after := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpSecretList,
		Input: json.RawMessage(`{"environmentId":"` + envID + `"}`),
	})
	if !after.OK {
		t.Fatalf("%+v", after)
	}
	afterRaw, _ := json.Marshal(after.Data)
	if strings.Contains(string(afterRaw), "API_TOKEN") {
		t.Fatalf("secret survived project delete %s", afterRaw)
	}
	events, err := aud.List("owner", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, e := range events {
		found[e.Action] = true
	}
	for _, action := range []string{"project.created", "environment.created", "secret.created", "project.deleted"} {
		if !found[action] {
			t.Fatalf("missing audit %s %+v", action, events)
		}
	}
	global := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGlobalSecretCreate,
		Input: json.RawMessage(`{"name":"GLOBAL_TOKEN","value":"global-secret-value","expectedGeneration":0}`),
	})
	if !global.OK {
		t.Fatalf("%+v", global)
	}
	globalRaw, _ := json.Marshal(global.Data)
	if bytes.Contains(globalRaw, []byte("global-secret-value")) {
		t.Fatalf("global plaintext %s", globalRaw)
	}
	if protocol.OpProjectList.Known() || protocol.OpSecretCreate.Known() || !protocol.OpProjectList.Dashboard() {
		t.Fatal("dashboard ops leaked onto public catalog")
	}
}

func TestDashboardSecretUnavailableWithoutKeyring(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "nokey.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	meta, err := metadata.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{NetworkProfile: protocol.NetworkNone}, nil, nil).WithMetadata(meta)
	listed := svc.Execute(t.Context(), protocol.RunnerRequest{Version: 2, OwnerID: "owner", Operation: protocol.OpGlobalSecretList})
	if !listed.OK {
		t.Fatalf("%+v", listed)
	}
	raw, _ := json.Marshal(listed.Data)
	if !bytes.Contains(raw, []byte(`"ready":false`)) {
		t.Fatalf("%s", raw)
	}
	created := svc.Execute(t.Context(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpGlobalSecretCreate,
		Input: json.RawMessage(`{"name":"API_TOKEN","value":"abcd","expectedGeneration":0}`),
	})
	if created.OK || created.Error == nil || created.Error.Code != protocol.ErrorUnavailable {
		t.Fatalf("%+v", created)
	}
}
