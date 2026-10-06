package runner

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/models"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func (s *Service) modelsDashboard(req protocol.RunnerRequest) protocol.ToolResult {
	if s.models == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "Model profile operations are temporarily unavailable", true)
	}
	now := time.Now().UnixMilli()
	switch req.Operation {
	case protocol.OpModelCredentialList:
		rows, err := s.models.ListCredentials(req.OwnerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.PublicJSON())
		}
		return protocol.Success("Model provider credentials listed", map[string]any{"credentials": out})
	case protocol.OpModelCredentialCreate:
		var input struct {
			Label     string `json:"label"`
			Provider  string `json:"provider"`
			AuthMode  string `json:"authMode"`
			APIKey    string `json:"apiKey"`
			SecretRef string `json:"secretReference"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid model_credential_create input", false)
		}
		row, err := s.models.CreateCredential(req.OwnerID, input.Label, input.Provider, input.AuthMode, input.APIKey, now)
		return modelMutation("Model provider credential created", row.PublicJSON(), err)
	case protocol.OpModelCredentialRotate:
		var input struct {
			CredentialID       string `json:"credentialId"`
			APIKey             string `json:"apiKey"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid model_credential_rotate input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixModelCredential, input.CredentialID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "credentialId is invalid", false)
		}
		row, err := s.models.RotateCredential(req.OwnerID, input.CredentialID, input.APIKey, input.ExpectedGeneration, now)
		return modelMutation("Model provider credential rotated", row.PublicJSON(), err)
	case protocol.OpModelCredentialDelete:
		var input struct {
			CredentialID       string `json:"credentialId"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid model_credential_delete input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixModelCredential, input.CredentialID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "credentialId is invalid", false)
		}
		if err := s.models.DeleteCredential(req.OwnerID, input.CredentialID, input.ExpectedGeneration); err != nil {
			return modelFail(err)
		}
		return protocol.Success("Model provider credential deleted", map[string]any{"deleted": true})
	case protocol.OpModelProfileList:
		rows, err := s.models.ListProfiles(req.OwnerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.PublicJSON())
		}
		return protocol.Success("Agent model profiles listed", map[string]any{"profiles": out})
	case protocol.OpModelProfileCreate:
		in, err := decodeProfileInput(req.Input, true)
		if err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid model_profile_create input", false)
		}
		row, err := s.models.CreateProfile(req.OwnerID, in, now)
		return modelMutation("Agent model profile created", row.PublicJSON(), err)
	case protocol.OpModelProfileUpdate:
		in, err := decodeProfileInput(req.Input, false)
		if err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid model_profile_update input", false)
		}
		row, err := s.models.UpdateProfile(req.OwnerID, in, now)
		return modelMutation("Agent model profile updated", row.PublicJSON(), err)
	case protocol.OpModelProfileActivate:
		id, gen, errRes := profileStatusInput(req.Input, "model_profile_activate")
		if errRes != nil {
			return *errRes
		}
		row, err := s.models.ActivateProfile(req.OwnerID, id, gen, now)
		return modelMutation("Agent model profile activated", row.PublicJSON(), err)
	case protocol.OpModelProfileDisable:
		id, gen, errRes := profileStatusInput(req.Input, "model_profile_disable")
		if errRes != nil {
			return *errRes
		}
		row, err := s.models.DisableProfile(req.OwnerID, id, gen, now)
		return modelMutation("Agent model profile disabled", row.PublicJSON(), err)
	case protocol.OpModelProfileDelete:
		id, gen, errRes := profileStatusInput(req.Input, "model_profile_delete")
		if errRes != nil {
			return *errRes
		}
		if err := s.models.DeleteProfile(req.OwnerID, id, gen); err != nil {
			return modelFail(err)
		}
		return protocol.Success("Agent model profile deleted", map[string]any{"deleted": true})
	case protocol.OpModelConfigStatus:
		profiles, creds, err := s.models.StatusCounts(req.OwnerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		return protocol.Success("Model configuration status", map[string]any{
			"status": map[string]any{
				"gatewaySynced":         false,
				"gatewayBootId":         nil,
				"lastSyncTime":          now,
				"activeProfileCount":    profiles,
				"activeCredentialCount": creds,
				"error":                 nil,
			},
		})
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

func profileStatusInput(raw json.RawMessage, op string) (string, int, *protocol.ToolResult) {
	var input struct {
		ProfileID          string `json:"profileId"`
		ExpectedGeneration int    `json:"expectedGeneration"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		res := protocol.Fail(protocol.ErrorInvalidInput, "invalid "+op+" input", false)
		return "", 0, &res
	}
	if !protocol.ValidModelProfileID(input.ProfileID) {
		res := protocol.Fail(protocol.ErrorInvalidInput, "profileId is invalid", false)
		return "", 0, &res
	}
	return input.ProfileID, input.ExpectedGeneration, nil
}

func decodeProfileInput(raw json.RawMessage, requireCreate bool) (models.ProfileInput, error) {
	var input struct {
		ProfileID          string   `json:"profileId"`
		DisplayName        string   `json:"displayName"`
		CredentialID       string   `json:"credentialId"`
		Model              string   `json:"model"`
		APIMode            string   `json:"apiMode"`
		CustomUpstreamURL  string   `json:"customUpstreamUrl"`
		MaxProxyOperations []string `json:"maxProxyOperations"`
		ExpectedGeneration int      `json:"expectedGeneration"`
		Pricing            *struct {
			InputMicrosPerMillionTokens  int `json:"inputMicrosPerMillionTokens"`
			OutputMicrosPerMillionTokens int `json:"outputMicrosPerMillionTokens"`
		} `json:"pricing"`
		Limits *struct {
			MaxInputTokens  int `json:"maxInputTokens"`
			MaxOutputTokens int `json:"maxOutputTokens"`
			MaxCostMicros   int `json:"maxCostMicros"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		return models.ProfileInput{}, err
	}
	if requireCreate && input.ProfileID == "" {
		return models.ProfileInput{}, errors.New("profileId required")
	}
	in := models.ProfileInput{
		ProfileID:          input.ProfileID,
		DisplayName:        input.DisplayName,
		CredentialID:       input.CredentialID,
		Model:              input.Model,
		APIMode:            input.APIMode,
		CustomUpstreamURL:  input.CustomUpstreamURL,
		MaxProxyOperations: input.MaxProxyOperations,
		ExpectedGeneration: input.ExpectedGeneration,
	}
	if input.Pricing != nil {
		in.Pricing = models.Pricing{
			InputMicrosPerMillionTokens:  input.Pricing.InputMicrosPerMillionTokens,
			OutputMicrosPerMillionTokens: input.Pricing.OutputMicrosPerMillionTokens,
		}
	}
	if input.Limits != nil {
		in.Limits = models.Limits{
			MaxInputTokens:  input.Limits.MaxInputTokens,
			MaxOutputTokens: input.Limits.MaxOutputTokens,
			MaxCostMicros:   input.Limits.MaxCostMicros,
		}
	}
	return in, nil
}

func modelMutation(message string, data map[string]any, err error) protocol.ToolResult {
	if err != nil {
		return modelFail(err)
	}
	return protocol.Success(message, data)
}

func modelFail(err error) protocol.ToolResult {
	if errors.Is(err, models.ErrNotFound) {
		return protocol.Fail(protocol.ErrorNotFound, err.Error(), false)
	}
	if errors.Is(err, models.ErrConflict) {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	if errors.Is(err, models.ErrInvalid) || strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "unsupported") {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
}
