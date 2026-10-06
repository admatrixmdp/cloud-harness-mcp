package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func testPEM() []byte {
	return []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK8=\n-----END RSA PRIVATE KEY-----\n")
}

func TestSecretFileThenEnvPrefersFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "github-app-private-key.pem")
	if err := os.WriteFile(path, []byte("  pem-from-file  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"GITHUB_APP_PRIVATE_KEY_FILE": path,
		"GITHUB_APP_PRIVATE_KEY":      "pem-from-env",
	}
	got := secretFileThenEnv(func(name string) string { return env[name] }, "GITHUB_APP_PRIVATE_KEY")
	if got != "pem-from-file" {
		t.Fatalf("got %q", got)
	}
}

func TestProductionServiceWiresClonerSQLiteAndGitHubApp(t *testing.T) {
	jobs := t.TempDir()
	state := filepath.Join(t.TempDir(), "state", "cloud-harness.db")
	pemPath := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(pemPath, testPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"JOBS_ROOT":                   jobs,
		"STATE_DB":                    state,
		"EXECUTOR_IMAGE":              "cloud-harness-executor:local",
		"INSTANCE_ID":                 "inst",
		"WORKSPACE_NETWORK_PROFILE":   "network-none",
		"GITHUB_APP_ID":               "123",
		"GITHUB_APP_INSTALLATION_ID":  "456",
		"GITHUB_APP_PRIVATE_KEY_FILE": pemPath,
		"RUNNER_TOKEN":                "r" + strings.Repeat("x", 31),
	}
	svc, err := ProductionService(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	if svc.cloner == nil {
		t.Fatal("cloner not wired")
	}
	if svc.cfg.GitHubApp.AppID != "123" || len(svc.cfg.GitHubApp.PrivateKey) == 0 {
		t.Fatal("github app not loaded from file")
	}
	if svc.mcpStore == nil {
		t.Fatal("mcp gateway store")
	}
	if token := ServiceTokenFromEnv(func(name string) string { return env[name] }); token != env["RUNNER_TOKEN"] {
		t.Fatalf("token %q", token)
	}
}

func TestProductionServiceLoadsAgentProfilesFromFile(t *testing.T) {
	jobs := t.TempDir()
	state := filepath.Join(t.TempDir(), "state.db")
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(`[
		{"id":"openai-default","displayName":"OpenAI","provider":"openai","model":"gpt-5.2-codex",
		 "inputMicrosPerMillionTokens":1,"outputMicrosPerMillionTokens":2,"maxInputTokens":400000,
		 "maxOutputTokens":128000,"maxCostMicros":100000000,"maxProxyOperations":["files_list","files_read"]}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"JOBS_ROOT":                 jobs,
		"STATE_DB":                  state,
		"EXECUTOR_IMAGE":            "cloud-harness-executor:local",
		"INSTANCE_ID":               "inst",
		"WORKSPACE_NETWORK_PROFILE": "network-none",
		"AGENT_IMAGE":               "cloud-harness-agent:local",
		"AGENT_GATEWAY_URL":         "http://model-gateway:3210",
		"AGENT_PROFILES_FILE":       path,
	}
	svc, err := ProductionService(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	if svc.agents.launcher == nil {
		t.Fatal("launcher")
	}
	got, ok := svc.agents.profiles["openai-default"]
	if !ok || got.Model != "gpt-5.2-codex" || got.Limits.MaxInputTokens != 400000 {
		t.Fatalf("%+v", got)
	}
	both := map[string]string{"AGENT_PROFILES_JSON": "[]", "AGENT_PROFILES_FILE": path}
	if _, err := loadAgentProfiles(func(name string) string { return both[name] }); err == nil || !strings.Contains(err.Error(), "configure only one") {
		t.Fatalf("both sources: %v", err)
	}
	missing := map[string]string{"AGENT_IMAGE": "cloud-harness-agent:local"}
	if _, err := ProductionService(func(name string) string {
		switch name {
		case "JOBS_ROOT":
			return jobs
		case "STATE_DB":
			return filepath.Join(t.TempDir(), "missing.db")
		case "EXECUTOR_IMAGE":
			return "cloud-harness-executor:local"
		case "AGENT_IMAGE":
			return missing["AGENT_IMAGE"]
		default:
			return ""
		}
	}); err == nil || !strings.Contains(err.Error(), "agent profiles must contain valid JSON") {
		t.Fatalf("missing profiles: %v", err)
	}
}

func TestProductionServiceCloneThenCreateMountsRepoNotSocket(t *testing.T) {
	jobs := t.TempDir()
	state := filepath.Join(t.TempDir(), "state.db")
	var calls [][]string
	env := map[string]string{
		"JOBS_ROOT":                 jobs,
		"STATE_DB":                  state,
		"EXECUTOR_IMAGE":            "cloud-harness-executor:local",
		"INSTANCE_ID":               "inst",
		"WORKSPACE_NETWORK_PROFILE": "network-none",
	}
	svc, err := ProductionService(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	run := func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
		calls = append(calls, append([]string{}, args...))
		if strings.Contains(stdin, "ghs_") {
			t.Fatal("token must not be minted without an app")
		}
		return sandbox.Result{ExitCode: 0}, nil
	}
	svc.docker.Run = run
	svc.cloner.Engine.Run = run
	got := svc.Execute(context.Background(), protocol.RunnerRequest{
		Version: 2, OwnerID: "owner", Operation: protocol.OpWorkspaceOpen,
		Input: json.RawMessage(`{"repositoryUrl":"https://github.com/bestagentkits/cloud-harness-mcp","idempotencyKey":"open-prod-001","networkProfile":"network-none"}`),
	})
	if !got.OK {
		t.Fatalf("%+v", got)
	}
	if len(calls) < 2 {
		t.Fatalf("expected clone then create, got %d: %v", len(calls), calls)
	}
	if !strings.Contains(strings.Join(calls[0], " "), "clone-helper.sh") {
		t.Fatalf("first call should clone: %v", calls[0])
	}
	if calls[1][0] != "create" {
		t.Fatalf("second call should create: %v", calls[1])
	}
	joined := strings.Join(calls[1], " ")
	if strings.Contains(joined, "docker.sock") || strings.Contains(joined, "--network bridge") {
		t.Fatalf("unsafe create: %s", joined)
	}
	wsID := got.Data.(map[string]any)["workspaceId"].(string)
	if !strings.Contains(joined, filepath.Join(jobs, wsID, "repo")+":/workspace:rw") {
		t.Fatalf("missing repo mount: %s", joined)
	}
}

func TestDockerEngineCreateMountsJobRepo(t *testing.T) {
	var got []string
	inner := &sandbox.Engine{
		Image:      "cloud-harness-executor:local",
		InstanceID: "inst",
		Run: func(_ context.Context, args []string, stdin string) (sandbox.Result, error) {
			got = append([]string{}, args...)
			if stdin != "" {
				t.Fatal("create must not send a token on stdin")
			}
			return sandbox.Result{ExitCode: 0}, nil
		},
	}
	eng := DockerEngine{Inner: inner, JobsRoot: "/var/lib/cloud-harness/jobs"}
	name, err := eng.Create(context.Background(), store.Record{
		ID:             "ws_abcdefghijklmnopqrstuvwx",
		NetworkProfile: protocol.NetworkNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "cloud-harness-ws-") {
		t.Fatalf("name %s", name)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "/var/lib/cloud-harness/jobs/ws_abcdefghijklmnopqrstuvwx/repo:/workspace:rw") {
		t.Fatalf("missing mount: %s", joined)
	}
	if strings.Contains(joined, "docker.sock") {
		t.Fatal("socket")
	}
}
