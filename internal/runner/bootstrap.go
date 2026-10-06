package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/agent"
	"github.com/bestagentkits/cloud-harness-mcp/internal/artifacts"
	"github.com/bestagentkits/cloud-harness-mcp/internal/audit"
	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
	"github.com/bestagentkits/cloud-harness-mcp/internal/githubapp"
	"github.com/bestagentkits/cloud-harness-mcp/internal/grants"
	"github.com/bestagentkits/cloud-harness-mcp/internal/hooks"
	"github.com/bestagentkits/cloud-harness-mcp/internal/integrations"
	"github.com/bestagentkits/cloud-harness-mcp/internal/knowledge"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcpgw"
	"github.com/bestagentkits/cloud-harness-mcp/internal/memories"
	"github.com/bestagentkits/cloud-harness-mcp/internal/metadata"
	"github.com/bestagentkits/cloud-harness-mcp/internal/models"
	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/internal/skillsreg"
	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
	"github.com/bestagentkits/cloud-harness-mcp/internal/typesafe"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// Env is a testable environment lookup. Production uses os.Getenv.
type Env func(string) string

func osEnv(name string) string { return os.Getenv(name) }

// secretFileThenEnv matches TS `secret()`: NAME_FILE wins, then NAME.
// Callers must not log the returned value.
func secretFileThenEnv(getenv Env, name string) string {
	if getenv == nil {
		getenv = osEnv
	}
	if file := strings.TrimSpace(getenv(name + "_FILE")); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(raw))
	}
	return strings.TrimSpace(getenv(name))
}

func csvEnv(getenv Env, name, fallback string) []string {
	raw := getenv(name)
	if raw == "" {
		raw = fallback
	}
	out := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return []string{fallback}
	}
	return out
}

func durationSeconds(getenv Env, name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return time.Duration(n) * time.Second
}

func githubAppFromEnv(getenv Env) git.AppConfig {
	return git.AppConfig{
		AppID:          strings.TrimSpace(getenv("GITHUB_APP_ID")),
		AppSlug:        strings.TrimSpace(getenv("GITHUB_APP_SLUG")),
		InstallationID: strings.TrimSpace(getenv("GITHUB_APP_INSTALLATION_ID")),
		PrivateKey:     []byte(secretFileThenEnv(getenv, "GITHUB_APP_PRIVATE_KEY")),
	}
}

// ServiceTokenFromEnv reads RUNNER_TOKEN(_FILE) then RUNNER_SERVICE_TOKEN(_FILE).
func ServiceTokenFromEnv(getenv Env) string {
	if getenv == nil {
		getenv = osEnv
	}
	if token := secretFileThenEnv(getenv, "RUNNER_TOKEN"); token != "" {
		return token
	}
	return secretFileThenEnv(getenv, "RUNNER_SERVICE_TOKEN")
}

type keyringFile struct {
	ActiveVersion int `json:"activeVersion"`
	Keys          []struct {
		Version int    `json:"version"`
		Key     string `json:"key"`
	} `json:"keys"`
}

func keyringFromEnv(getenv Env) (*secrets.Keyring, error) {
	raw := secretFileThenEnv(getenv, "SECRET_KEYRING")
	if raw == "" {
		return nil, nil
	}
	var parsed keyringFile
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("secret keyring configuration is invalid")
	}
	configured := make([]secrets.KeyConfig, 0, len(parsed.Keys))
	for _, item := range parsed.Keys {
		configured = append(configured, secrets.KeyConfig{Version: item.Version, Key: []byte(item.Key)})
	}
	return secrets.NewKeyring(parsed.ActiveVersion, configured)
}

// ProductionService wires Docker clone, GitHub App minting, durable SQLite,
// and optional TypeSafe. Tests inject getenv; production uses the process env.
func ProductionService(getenv Env) (*Service, error) {
	if getenv == nil {
		getenv = osEnv
	}
	profile := protocol.NetworkProfile(getenv("WORKSPACE_NETWORK_PROFILE"))
	if profile == "" {
		profile = sandbox.DefaultNetworkProfile
	}
	jobsRoot := getenv("JOBS_ROOT")
	if jobsRoot == "" {
		jobsRoot = "/var/lib/cloud-harness/jobs"
	}
	image := getenv("EXECUTOR_IMAGE")
	if image == "" {
		image = "cloud-harness-executor:local"
	}
	instanceID := getenv("INSTANCE_ID")
	if instanceID == "" {
		instanceID = "local"
	}
	docker := &sandbox.Engine{Image: image, InstanceID: instanceID}
	guardImage := strings.TrimSpace(getenv("NETWORK_GUARD_IMAGE"))
	if guardImage == "" {
		guardImage = sandbox.DefaultGuardImage
	}
	cfg := Config{
		AllowedGitHosts:          csvEnv(getenv, "ALLOWED_GIT_HOSTS", "github.com"),
		NetworkProfile:           profile,
		IdleTTL:                  durationSeconds(getenv, "WORKSPACE_IDLE_TTL_SECONDS", 5*time.Minute),
		WallTTL:                  durationSeconds(getenv, "WORKSPACE_WALL_TTL_SECONDS", 15*time.Minute),
		InstanceID:               instanceID,
		JobsRoot:                 jobsRoot,
		ExecutorImage:            image,
		GitHubApp:                githubAppFromEnv(getenv),
		AgentKitKeyID:            strings.TrimSpace(getenv("AGENTKIT_REGISTRY_KEY_ID")),
		AgentKitPublicKey:        strings.TrimSpace(getenv("AGENTKIT_REGISTRY_PUBLIC_KEY")),
		AgentKitCredentialSecret: strings.TrimSpace(getenv("AGENTKIT_REGISTRY_CREDENTIAL_SECRET")),
		Attestor: sandbox.FirewallAttestor{
			NetworkName:     strings.TrimSpace(getenv("DEPENDENCY_NETWORK_NAME")),
			BridgeInterface: strings.TrimSpace(getenv("DEPENDENCY_BRIDGE_INTERFACE")),
			BridgeSubnet:    strings.TrimSpace(getenv("DEPENDENCY_BRIDGE_SUBNET")),
			DNSResolvers:    csvEnv(getenv, "DEPENDENCY_DNS_RESOLVERS", "8.8.8.8,1.1.1.1"),
			GuardImage:      guardImage,
			Run: func(ctx context.Context, args []string, stdin string) (sandbox.Result, error) {
				return docker.Invoke(ctx, args, stdin)
			},
		},
	}
	var st store.Store
	var sqlite *store.SQLite
	if stateDB := getenv("STATE_DB"); stateDB != "" {
		opened, err := store.OpenSQLite(stateDB)
		if err != nil {
			return nil, err
		}
		sqlite = opened
		st = opened
	}
	svc := NewService(cfg, st, DockerEngine{Inner: docker, JobsRoot: jobsRoot}).
		WithDocker(docker).
		WithCloner(&git.Cloner{Engine: *docker})
	if sqlite != nil {
		db := sqlite.DB()
		gw, err := mcpgw.Open(db)
		if err != nil {
			return nil, err
		}
		svc = svc.WithMCPGateway(gw)
		if grantStore, err := grants.Open(db); err == nil {
			svc = svc.WithGrants(grantStore)
		}
		if auditStore, err := audit.Open(db); err == nil {
			svc = svc.WithAudit(auditStore)
		}
		if ghStore, err := githubapp.Open(db); err == nil {
			var verifier GitHubVerifier
			if cfg.GitHubApp.AppID != "" && len(cfg.GitHubApp.PrivateKey) > 0 {
				verifier = githubapp.NewHTTPVerifier(cfg.GitHubApp, cfg.HTTP)
			}
			svc = svc.WithGitHub(ghStore, verifier)
		}
		if hookStore, err := hooks.Open(db); err == nil {
			svc = svc.WithHooks(hookStore)
		}
		if memStore, err := memories.Open(db); err == nil {
			svc = svc.WithMemories(memStore)
		}
		if knowledgeStore, err := knowledge.Open(db); err == nil {
			svc = svc.WithKnowledge(knowledgeStore)
		}
		if skillStore, err := skillsreg.Open(db); err == nil {
			svc = svc.WithSkills(skillStore)
		}
		if meta, err := metadata.Open(db); err == nil {
			svc = svc.WithMetadata(meta)
		}
		if ring, err := keyringFromEnv(getenv); err != nil {
			return nil, err
		} else if ring != nil {
			sec, err := secrets.OpenMetadata(db, ring)
			if err != nil {
				return nil, err
			}
			svc = svc.WithSecrets(sec)
			modelStore, err := models.Open(db, ring)
			if err != nil {
				return nil, err
			}
			svc = svc.WithModels(modelStore)
			intStore, err := integrations.Open(db, ring)
			if err != nil {
				return nil, err
			}
			svc = svc.WithIntegrations(intStore)
		}
		if root := getenv("ARTIFACT_ROOT"); root != "" {
			art, err := artifacts.Open(db, artifacts.Options{Root: root})
			if err != nil {
				return nil, err
			}
			svc = svc.WithArtifacts(art)
		}
	}
	if key := secretFileThenEnv(getenv, "TYPESAFE_API_KEY"); key != "" {
		svc = svc.WithTypeSafe(typesafe.New(typesafe.Config{APIKey: func() string { return key }}))
	}
	if image := strings.TrimSpace(getenv("AGENT_IMAGE")); image != "" {
		gatewayURL := strings.TrimSpace(getenv("AGENT_GATEWAY_URL"))
		if gatewayURL == "" {
			gatewayURL = "http://model-gateway:3210"
		}
		launcher := &agent.Launcher{
			Docker:     docker,
			InstanceID: instanceID,
			Image:      image,
			GatewayURL: gatewayURL,
			GatewayCtr: strings.TrimSpace(getenv("AGENT_GATEWAY_CONTAINER")),
		}
		var gateway *agent.ControlClient
		if sock := strings.TrimSpace(getenv("MODEL_GATEWAY_CONTROL_SOCKET")); sock != "" {
			gateway = &agent.ControlClient{Path: sock}
		}
		profiles, err := loadAgentProfiles(getenv)
		if err != nil {
			return nil, err
		}
		svc = svc.WithAgents(launcher, gateway, profiles)
	}
	return svc, nil
}

type agentProfileFile struct {
	ID                           string   `json:"id"`
	DisplayName                  string   `json:"displayName"`
	Provider                     string   `json:"provider"`
	Model                        string   `json:"model"`
	APIMode                      string   `json:"apiMode"`
	InputMicrosPerMillionTokens  int64    `json:"inputMicrosPerMillionTokens"`
	OutputMicrosPerMillionTokens int64    `json:"outputMicrosPerMillionTokens"`
	MaxInputTokens               int      `json:"maxInputTokens"`
	MaxOutputTokens              int      `json:"maxOutputTokens"`
	MaxCostMicros                int64    `json:"maxCostMicros"`
	MaxProxyOperations           []string `json:"maxProxyOperations"`
}

func loadAgentProfiles(getenv Env) (map[string]agent.Profile, error) {
	jsonValue := strings.TrimSpace(getenv("AGENT_PROFILES_JSON"))
	fileValue := strings.TrimSpace(getenv("AGENT_PROFILES_FILE"))
	if jsonValue != "" && fileValue != "" {
		return nil, fmt.Errorf("configure only one of AGENT_PROFILES_JSON or AGENT_PROFILES_FILE")
	}
	serialized := jsonValue
	if serialized == "" && fileValue != "" {
		raw, err := os.ReadFile(fileValue)
		if err != nil {
			return nil, fmt.Errorf("agent profiles must contain valid JSON")
		}
		serialized = string(raw)
	}
	if serialized == "" {
		return nil, fmt.Errorf("agent profiles must contain valid JSON")
	}
	var rows []agentProfileFile
	if err := json.Unmarshal([]byte(serialized), &rows); err != nil {
		return nil, fmt.Errorf("agent profiles must contain valid JSON")
	}
	out := map[string]agent.Profile{}
	for _, row := range rows {
		if !protocol.ValidModelProfileID(row.ID) {
			return nil, fmt.Errorf("agent profiles must contain valid JSON")
		}
		if _, dup := out[row.ID]; dup {
			return nil, fmt.Errorf("agent profile IDs must be unique")
		}
		apiMode := row.APIMode
		if apiMode == "" {
			apiMode = "chat-completions"
		}
		out[row.ID] = agent.Profile{
			ID:                     row.ID,
			DisplayName:            row.DisplayName,
			Provider:               row.Provider,
			Model:                  row.Model,
			APIMode:                apiMode,
			InputMicrosPerMillion:  row.InputMicrosPerMillionTokens,
			OutputMicrosPerMillion: row.OutputMicrosPerMillionTokens,
			Limits: agent.ProfileLimits{
				MaxInputTokens:  row.MaxInputTokens,
				MaxOutputTokens: row.MaxOutputTokens,
				MaxCostMicros:   row.MaxCostMicros,
			},
			MaxProxyOperations: append([]string{}, row.MaxProxyOperations...),
		}
	}
	return out, nil
}
