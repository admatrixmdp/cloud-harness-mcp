package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlIssueRevokeDoesNotLogLease(t *testing.T) {
	sock := filepath.Join("/tmp", "ch-gw-"+strings.ReplaceAll(t.Name(), "/", "-")+".sock")
	_ = os.Remove(sock)
	t.Cleanup(func() { _ = os.Remove(sock) })
	reg := NewRegistry()
	profile := Profile{ID: "coding-fast", Limits: ProfileLimits{MaxInputTokens: 100, MaxOutputTokens: 50, MaxCostMicros: 1_000}}
	srv := &ControlServer{Path: sock, Registry: reg, Profiles: map[string]Profile{"coding-fast": profile}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
		default:
		}
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}
	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	client := &ControlClient{Path: sock}
	agentID := "agent_" + strings.Repeat("a", 24)
	token, err := client.Issue(ctx, IssueInput{
		LeaseID: "lease_control_1", AgentID: agentID, ProfileID: "coding-fast",
		TTL: time.Minute, MaxInputTokens: 10, MaxOutputTokens: 10, MaxCostMicros: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 43 {
		t.Fatalf("token too short")
	}
	if _, err := reg.Consume(token, agentID, "coding-fast"); err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(ctx, "lease_control_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Consume(token, agentID, "coding-fast"); err == nil {
		t.Fatal("revoked lease still usable")
	}
	redacted := RedactControlJSON(`{"ok":true,"lease":"` + token + `"}`)
	if strings.Contains(redacted, token) {
		t.Fatal("lease leaked into log redaction")
	}
	cancel()
}

func waitSock(t *testing.T, sock string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
		default:
		}
		if _, err := os.Stat(sock); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestControlApplySnapshotIssuesLeaseAndRefusesPrivateProductionUpstream(t *testing.T) {
	sock := filepath.Join("/tmp", "ch-gw-"+strings.ReplaceAll(t.Name(), "/", "-")+".sock")
	_ = os.Remove(sock)
	t.Cleanup(func() { _ = os.Remove(sock) })
	live := NewLiveRegistry(false)
	srv := &ControlServer{Path: sock, Registry: NewRegistry(), Live: live}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitSock(t, sock, errCh)
	client := &ControlClient{Path: sock}

	rev, _ := json.Marshal(map[string]any{
		"id": "rev_dynamic_1", "profileId": "coding-fast", "credentialId": "cred_test_1",
		"model": "gpt-5.2-codex", "apiMode": "chat-completions", "downstreamPath": "/v1/chat/completions",
		"upstreamUrl": "https://api.openai.com/v1/chat/completions",
		"pricing":     map[string]any{"inputMicrosPerMillionTokens": 1000, "outputMicrosPerMillionTokens": 2000},
		"limits":      map[string]any{"maxInputTokens": 50000, "maxOutputTokens": 2000, "maxCostMicros": 100000},
	})
	ack, err := client.ApplySnapshot(ctx, Snapshot{
		Sequence: 1, Generation: 1,
		Credentials: map[string]SnapshotCredential{
			"cred_test_1": {Provider: "openai", AuthMode: "bearer", Secret: "sk-dynamic-test-key-999"},
		},
		Profiles: map[string]json.RawMessage{"rev_dynamic_1": rev},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ack.SnapshotDigest, "sha256:") || ack.ActiveProfileCount != 1 {
		t.Fatalf("%+v", ack)
	}
	if strings.Contains(ack.SnapshotDigest, "sk-dynamic-test-key-999") {
		t.Fatal("secret leaked into digest")
	}
	agentID := "agent_" + strings.Repeat("b", 24)
	token, err := client.Issue(ctx, IssueInput{
		LeaseID: "lease_dynamic_1", AgentID: agentID, ProfileID: "rev_dynamic_1",
		TTL: time.Minute, MaxInputTokens: 10, MaxOutputTokens: 10, MaxCostMicros: 10,
	})
	if err != nil || len(token) < 43 {
		t.Fatalf("issue %q %v", token, err)
	}
	digest, err := client.QueryDigest(ctx)
	if err != nil || digest.ActiveLeaseCount != 1 || digest.GatewayBootID == "" {
		t.Fatalf("%+v %v", digest, err)
	}

	private, _ := json.Marshal(map[string]any{
		"id": "rev_private", "profileId": "coding-fast", "credentialId": "cred_test_1",
		"model": "gpt-5.2-codex", "apiMode": "chat-completions", "downstreamPath": "/v1/chat/completions",
		"upstreamUrl": "https://127.0.0.1:3443/v1/chat/completions",
		"pricing":     map[string]any{"inputMicrosPerMillionTokens": 1, "outputMicrosPerMillionTokens": 1},
		"limits":      map[string]any{"maxInputTokens": 10, "maxOutputTokens": 10, "maxCostMicros": 10},
	})
	if _, err := client.ApplySnapshot(ctx, Snapshot{
		Sequence: 2, Generation: 1,
		Credentials: map[string]SnapshotCredential{"cred_test_1": {Provider: "openai", AuthMode: "bearer", Secret: "sk-dynamic-test-key-999"}},
		Profiles:    map[string]json.RawMessage{"rev_private": private},
	}); err == nil || !strings.Contains(err.Error(), "private or reserved") {
		t.Fatalf("expected private refusal, got %v", err)
	}
	digest, err = client.QueryDigest(ctx)
	if err != nil || digest.ActiveProfileCount != 1 {
		t.Fatalf("failed snapshot must not commit %+v %v", digest, err)
	}
	redacted := RedactControlJSON(`{"ok":true,"secret":"sk-dynamic-test-key-999"}`)
	if strings.Contains(redacted, "sk-dynamic-test-key-999") {
		t.Fatal("secret leaked into log redaction")
	}
}
