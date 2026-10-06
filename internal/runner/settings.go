package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var toolkitCatalog = []map[string]any{
	{
		"id": "mattpocock/skills", "name": "Matt Pocock Skills",
		"description":     "53 real engineering skills including TDD, diagnosing bugs, and codebase architecture.",
		"defaultRevision": "main", "adapterVersion": 1, "license": "MIT",
		"sourceUrl":       "https://github.com/mattpocock/skills.git",
		"supportedScopes": []string{"owner", "workspace"}, "activation": "toolkit-default",
	},
	{
		"id": "obra/superpowers", "name": "Superpowers",
		"description":     "Agentic skills framework and session-start tool mapping instructions.",
		"defaultRevision": "main", "adapterVersion": 1, "license": "MIT",
		"sourceUrl":       "https://github.com/obra/superpowers.git",
		"supportedScopes": []string{"owner", "workspace"}, "activation": "toolkit-default",
	},
}

var licensedKitCatalog = []struct {
	kitID, name, description, channel string
}{
	{"engineer", "AgentKit Engineer", "Engineer-specialized licensed kit: extends the core kit with engineer-unique agents, skills, hooks, schemas, and scripts.", "stable"},
	{"marketing", "AgentKit Marketing", "Marketing-specialized licensed kit: extends the core kit with marketing-unique agents, skills, hooks, and scripts.", "stable"},
}

func (s *Service) settingsDashboard(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	switch req.Operation {
	case protocol.OpToolkitsList:
		return protocol.Success("Catalog toolkits list", map[string]any{
			"toolkits":     toolkitCatalog,
			"licensedKits": s.licensedKitCatalog(req.OwnerID),
		})
	case protocol.OpToolkitsPreview:
		var input struct {
			Toolkits []map[string]any `json:"toolkits"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid toolkits_preview input", false)
		}
		if len(input.Toolkits) > 8 {
			return protocol.Fail(protocol.ErrorInvalidInput, "toolkits must contain at most 8 selections", false)
		}
		return protocol.Success("Toolkits preview", map[string]any{
			"requestFingerprint": toolkitFingerprint(input.Toolkits),
			"toolkitsCount":      len(input.Toolkits),
		})
	case protocol.OpSettingsGet:
		return protocol.Success("Instance workspace settings", s.settingsJSON())
	case protocol.OpSettingsUpdate:
		var raw map[string]any
		if err := json.Unmarshal(req.Input, &raw); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid settings_update input", false)
		}
		value, present := raw["defaultNetworkProfile"]
		if !present || len(raw) != 1 {
			return protocol.Fail(protocol.ErrorInvalidInput, "The default network profile must be network-none or dependency-access.", false)
		}
		previous, previousOK := s.store.DefaultNetworkProfile()
		previousLabel := "runner-default"
		if previousOK {
			previousLabel = string(previous)
		}
		nextLabel := "runner-default"
		var stored *protocol.NetworkProfile
		if value != nil {
			text, _ := value.(string)
			profile := protocol.NetworkProfile(text)
			if !profile.Valid() {
				return protocol.Fail(protocol.ErrorInvalidInput, "The default network profile must be network-none or dependency-access.", false)
			}
			stored = &profile
			nextLabel = string(profile)
		}
		s.store.SetDefaultNetworkProfile(stored, time.Now())
		if s.audit != nil {
			_, _ = s.audit.Record(req.OwnerID, "settings.default_network_profile.changed", "instance", "instance_settings", 1, map[string]any{
				"previous": previousLabel, "next": nextLabel,
			})
		}
		return protocol.Success("Instance workspace settings", s.settingsJSON())
	case protocol.OpSettingsNetworkCheck:
		ready := true
		var reason any
		if s.cfg.Attestor == nil {
			ready = false
			reason = "attestation not configured"
		} else {
			ok, why, err := s.cfg.Attestor.Verify(ctx)
			if err != nil {
				ready = false
				reason = "attestation probe failed"
			} else if !ok {
				ready = false
				if why == "" {
					why = "verification failed"
				}
				reason = why
			}
		}
		return protocol.Success("Dependency egress readiness", map[string]any{"ready": ready, "reason": reason})
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

func (s *Service) settingsJSON() map[string]any {
	value := s.cfg.NetworkProfile
	source := "environment"
	if stored, ok := s.store.DefaultNetworkProfile(); ok {
		value = stored
		source = "setting"
	}
	return map[string]any{
		"defaultNetworkProfile": map[string]any{"value": string(value), "source": source},
	}
}

func (s *Service) resolvedDefaultNetworkProfile() protocol.NetworkProfile {
	if stored, ok := s.store.DefaultNetworkProfile(); ok {
		return stored
	}
	return s.cfg.NetworkProfile
}

func (s *Service) licensedKitCatalog(ownerID string) []map[string]any {
	secretName := strings.TrimSpace(s.cfg.AgentKitCredentialSecret)
	if secretName == "" {
		secretName = "AGENTKIT_REGISTRY_TOKEN"
	}
	available := strings.TrimSpace(s.cfg.AgentKitKeyID) != "" && strings.TrimSpace(s.cfg.AgentKitPublicKey) != ""
	credentialReady := false
	if s.secrets != nil {
		if rows, err := s.secrets.ListGlobal(ownerID); err == nil {
			for _, row := range rows {
				if row.Name == secretName && row.Purpose == "provisioning" && row.State == "ACTIVE" {
					credentialReady = true
					break
				}
			}
		}
	}
	out := make([]map[string]any, 0, len(licensedKitCatalog))
	for _, kit := range licensedKitCatalog {
		out = append(out, map[string]any{
			"kind":                     "agentkit",
			"kitId":                    kit.kitID,
			"name":                     kit.name,
			"description":              kit.description,
			"defaultChannel":           kit.channel,
			"available":                available,
			"credentialReady":          credentialReady,
			"requiresCredentialSecret": secretName,
			"supportedScopes":          []string{"owner"},
			"activation":               "skills-only",
			"verification":             "registry-signed",
		})
	}
	return out
}

func toolkitFingerprint(toolkits []map[string]any) string {
	type keyed struct {
		id  string
		raw map[string]any
	}
	items := make([]keyed, 0, len(toolkits))
	for _, toolkit := range toolkits {
		items = append(items, keyed{id: toolkitIdentity(toolkit), raw: toolkit})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].id < items[j].id })
	canonical := make([]map[string]any, 0, len(items))
	for _, item := range items {
		canonical = append(canonical, item.raw)
	}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func toolkitIdentity(selection map[string]any) string {
	if id, _ := selection["instanceId"].(string); id != "" {
		return id
	}
	kind, _ := selection["kind"].(string)
	switch kind {
	case "preset":
		id, _ := selection["id"].(string)
		return id
	case "agentkit":
		kit, _ := selection["kitId"].(string)
		channel, _ := selection["channel"].(string)
		if channel == "" {
			channel = "stable"
		}
		return "agentkit:" + kit + ":" + channel
	default:
		id, _ := selection["instanceId"].(string)
		return id
	}
}
