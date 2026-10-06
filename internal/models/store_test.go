package models

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"

	_ "modernc.org/sqlite"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "models.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ring, err := secrets.NewKeyring(1, []secrets.KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{3}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	store, err := Open(db, ring)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestCreateListRotateDeleteCredentialNeverProjectsAPIKey(t *testing.T) {
	store := openStore(t)
	now := int64(1_700_000_000_000)
	created, err := store.CreateCredential("owner", "OpenAI Prod", "openai", "", "sk-prod-secret-12345", now)
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.ValidOpaqueID(protocol.PrefixModelCredential, created.ID) {
		t.Fatalf("%s", created.ID)
	}
	raw, _ := json.Marshal(created.PublicJSON())
	if bytes.Contains(raw, []byte("sk-prod-secret-12345")) || bytes.Contains(raw, []byte(`"apiKey"`)) {
		t.Fatalf("plaintext leaked %s", raw)
	}
	listed, err := store.ListCredentials("owner")
	if err != nil || len(listed) != 1 {
		t.Fatalf("%v %#v", err, listed)
	}
	other, err := store.ListCredentials("other")
	if err != nil || len(other) != 0 {
		t.Fatalf("isolation %#v", other)
	}
	rotated, err := store.RotateCredential("owner", created.ID, "sk-new-secret-67890", 1, now+1)
	if err != nil || rotated.ActiveVersion != 2 || rotated.Generation != 2 {
		t.Fatalf("%v %#v", err, rotated)
	}
	if _, err := store.RotateCredential("owner", created.ID, "sk-fail", 1, now+2); err == nil {
		t.Fatal("stale generation")
	}
	plain, err := store.DecryptCredential("owner", created.ID)
	if err != nil || plain != "sk-new-secret-67890" {
		t.Fatalf("decrypt %q %v", plain, err)
	}
	if err := store.DeleteCredential("owner", created.ID, 2); err != nil {
		t.Fatal(err)
	}
	after, err := store.ListCredentials("owner")
	if err != nil || len(after) != 0 {
		t.Fatalf("%v %#v", err, after)
	}
}

func TestProfilesImmutableRevisionsAndCredentialRef(t *testing.T) {
	store := openStore(t)
	now := int64(1_700_000_000_000)
	cred, err := store.CreateCredential("owner", "OpenAI Test", "openai", "bearer", "sk-12345", now)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := store.CreateProfile("owner", ProfileInput{
		ProfileID: "coding-fast", DisplayName: "Fast Coding", CredentialID: cred.ID,
		Model: "gpt-5.2-codex", APIMode: "chat-completions",
		Pricing:            Pricing{InputMicrosPerMillionTokens: 1000, OutputMicrosPerMillionTokens: 2000},
		Limits:             Limits{MaxInputTokens: 10000, MaxOutputTokens: 2000, MaxCostMicros: 50000},
		MaxProxyOperations: []string{"files_read", "grep_search"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Status != "ACTIVE" || profile.ActiveRevision == nil || profile.ActiveRevision.Model != "gpt-5.2-codex" {
		t.Fatalf("%#v", profile)
	}
	if profile.ActiveRevision.UpstreamURL != "https://api.openai.com/v1/chat/completions" {
		t.Fatalf("%s", profile.ActiveRevision.UpstreamURL)
	}
	if err := store.DeleteCredential("owner", cred.ID, 1); err == nil {
		t.Fatal("referenced credential deleted")
	}
	updated, err := store.UpdateProfile("owner", ProfileInput{
		ProfileID: "coding-fast", DisplayName: "Fast Coding v2",
		Pricing:            Pricing{InputMicrosPerMillionTokens: 1200, OutputMicrosPerMillionTokens: 2400},
		ExpectedGeneration: 1,
	}, now+1)
	if err != nil || updated.Generation != 2 {
		t.Fatalf("%v %#v", err, updated)
	}
	if asInt(updated.ActiveRevision.Pricing["inputMicrosPerMillionTokens"]) != 1200 {
		t.Fatalf("%#v", updated.ActiveRevision.Pricing)
	}
	if updated.ActiveRevision.Model != "gpt-5.2-codex" {
		t.Fatalf("model dropped %s", updated.ActiveRevision.Model)
	}
	disabled, err := store.DisableProfile("owner", "coding-fast", 2, now+2)
	if err != nil || disabled.Status != "DISABLED" {
		t.Fatalf("%v %#v", err, disabled)
	}
	activated, err := store.ActivateProfile("owner", "coding-fast", 3, now+3)
	if err != nil || activated.Status != "ACTIVE" {
		t.Fatalf("%v %#v", err, activated)
	}
	other, err := store.ListProfiles("other")
	if err != nil || len(other) != 0 {
		t.Fatalf("isolation %#v", other)
	}
	if err := store.DeleteProfile("owner", "coding-fast", 4); err != nil {
		t.Fatal(err)
	}
	after, err := store.ListProfiles("owner")
	if err != nil || len(after) != 0 {
		t.Fatalf("%v %#v", err, after)
	}
}

func TestCustomUpstreamRequiresHTTPS443(t *testing.T) {
	store := openStore(t)
	now := int64(1)
	cred, err := store.CreateCredential("owner", "Custom", "custom", "bearer", "tok", now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateProfile("owner", ProfileInput{
		ProfileID: "custom-one", DisplayName: "Custom", CredentialID: cred.ID,
		Model: "local", APIMode: "chat-completions", CustomUpstreamURL: "http://example.com/v1",
		Pricing: Pricing{}, Limits: Limits{MaxInputTokens: 1, MaxOutputTokens: 1, MaxCostMicros: 1},
		MaxProxyOperations: []string{"files_read"},
	}, now)
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("%v", err)
	}
}
