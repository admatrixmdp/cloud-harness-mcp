package agent

import (
	"strings"
	"testing"
	"time"
)

func TestIssueConsumeRevoke(t *testing.T) {
	reg := NewRegistry()
	profile := Profile{ID: "gpt-test", Limits: ProfileLimits{MaxInputTokens: 1000, MaxOutputTokens: 200, MaxCostMicros: 50_000}}
	agentID := "agent_" + strings.Repeat("a", 24)
	token, err := reg.Issue(IssueInput{
		LeaseID: "lease-1", AgentID: agentID, ProfileID: "gpt-test",
		TTL: 5 * time.Minute, MaxInputTokens: 500, MaxOutputTokens: 100, MaxCostMicros: 10_000,
	}, profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 43 {
		t.Fatalf("token too short: %s", token)
	}
	if strings.Contains(token, agentID) {
		t.Fatal("lease token echoed agent id")
	}
	if _, err := reg.Consume(token, "agent_"+strings.Repeat("b", 24), "gpt-test"); err == nil {
		t.Fatal("wrong agent accepted")
	}
	grant, err := reg.Consume(token, agentID, "gpt-test")
	if err != nil {
		t.Fatal(err)
	}
	if grant.AgentID != agentID || grant.RemainingInputTokens != 500 {
		t.Fatalf("%+v", grant)
	}
	if _, err := reg.Consume(token, agentID, "gpt-test"); err != nil {
		t.Fatal("active reuse should succeed")
	}
	if !reg.Revoke("lease-1") {
		t.Fatal("revoke")
	}
	if _, err := reg.Consume(token, agentID, "gpt-test"); err == nil {
		t.Fatal("revoked replay accepted")
	}
}

func TestIssueRejectsBadIDsAndCapacity(t *testing.T) {
	reg := NewRegistry()
	profile := Profile{ID: "p", Limits: ProfileLimits{MaxInputTokens: 10, MaxOutputTokens: 10, MaxCostMicros: 10}}
	if _, err := reg.Issue(IssueInput{LeaseID: "bad id", AgentID: "agent_" + strings.Repeat("a", 24), ProfileID: "p", TTL: time.Minute, MaxInputTokens: 1, MaxOutputTokens: 1}, profile); err == nil {
		t.Fatal("spaces in leaseId")
	}
	if _, err := reg.Issue(IssueInput{LeaseID: "ok", AgentID: "not-an-agent", ProfileID: "p", TTL: time.Minute, MaxInputTokens: 1, MaxOutputTokens: 1}, profile); err == nil {
		t.Fatal("bad agentId")
	}
	if _, err := reg.Issue(IssueInput{LeaseID: "ok", AgentID: "agent_" + strings.Repeat("a", 24), ProfileID: "other", TTL: time.Minute, MaxInputTokens: 1, MaxOutputTokens: 1}, profile); err == nil {
		t.Fatal("profile mismatch")
	}
}
