package agent

import (
	"context"
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
