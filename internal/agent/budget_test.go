package agent

import (
	"testing"
)

func TestReserveBudgetClampsAndRejectsOverspend(t *testing.T) {
	profile := Profile{
		ID: "gpt-test", Model: "gpt-test", DownstreamPath: "/v1/chat/completions",
		InputMicrosPerMillion: 1_000_000, OutputMicrosPerMillion: 2_000_000,
		Limits: ProfileLimits{MaxInputTokens: 100, MaxOutputTokens: 50, MaxCostMicros: 1_000_000},
	}
	grant := Grant{RemainingInputTokens: 80, RemainingOutputTokens: 40, RemainingCostMicros: 200}
	body := map[string]any{"model": "ignored", "max_tokens": 100.0}
	res, err := grant.reserve(body, 10, profile, "/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	if body["model"] != "gpt-test" {
		t.Fatalf("model %v", body["model"])
	}
	if body["max_tokens"] != res.OutputTokens {
		t.Fatalf("clamped %v vs %d", body["max_tokens"], res.OutputTokens)
	}
	if _, ok := body["stream_options"]; !ok {
		t.Fatal("stream_options missing")
	}
	if grant.RemainingInputTokens != 80-res.InputTokens {
		t.Fatalf("input remaining %d", grant.RemainingInputTokens)
	}
	broke := Grant{RemainingInputTokens: 5, RemainingOutputTokens: 40, RemainingCostMicros: 1_000_000}
	if _, err := broke.reserve(map[string]any{}, 20, profile, "/v1/chat/completions"); err == nil {
		t.Fatal("oversize input must fail")
	}
	cheap := Grant{RemainingInputTokens: 80, RemainingOutputTokens: 40, RemainingCostMicros: 0}
	if _, err := cheap.reserve(map[string]any{}, 10, profile, "/v1/chat/completions"); err == nil {
		t.Fatal("zero remaining cost must fail")
	}
}

func TestReconcileBudgetRefundsUnused(t *testing.T) {
	grant := Grant{RemainingInputTokens: 10, RemainingOutputTokens: 5, RemainingCostMicros: 100}
	res := Reservation{InputTokens: 40, OutputTokens: 20, CostMicros: 50}
	actual := &ProviderUsage{InputTokens: 10, OutputTokens: 4, CostMicros: 12}
	used := grant.reconcile(res, actual)
	if used.InputTokens != 10 || used.OutputTokens != 4 || used.CostMicros != 12 {
		t.Fatalf("%+v", used)
	}
	if grant.RemainingInputTokens != 40 || grant.RemainingOutputTokens != 21 || grant.RemainingCostMicros != 138 {
		t.Fatalf("%+v", grant)
	}
}

func TestUsageFromProvider(t *testing.T) {
	profile := Profile{InputMicrosPerMillion: 1_000_000, OutputMicrosPerMillion: 2_000_000}
	got := usageFromProvider([]byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`), profile)
	if got == nil || got.InputTokens != 2 || got.OutputTokens != 3 || got.CostMicros != 8 {
		t.Fatalf("%+v", got)
	}
}
