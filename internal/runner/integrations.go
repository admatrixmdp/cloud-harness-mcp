package runner

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/integrations"
	"github.com/bestagentkits/cloud-harness-mcp/internal/typesafe"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func (s *Service) integrationsDashboard(req protocol.RunnerRequest) protocol.ToolResult {
	if s.integrations == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "Integration credential operations are temporarily unavailable", true)
	}
	now := time.Now().UnixMilli()
	switch req.Operation {
	case protocol.OpIntegrationCredentialList:
		rows, err := s.integrations.List(req.OwnerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.PublicJSON())
		}
		return protocol.Success("Integration credentials listed", map[string]any{"credentials": out})
	case protocol.OpIntegrationCredentialCreate:
		var input struct {
			Integration        string `json:"integration"`
			Label              string `json:"label"`
			Value              string `json:"value"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid integration_credential_create input", false)
		}
		if input.ExpectedGeneration != 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "expectedGeneration must be 0", false)
		}
		row, err := s.integrations.Create(req.OwnerID, input.Integration, input.Label, input.Value, now)
		return integrationMutation("Integration credential created", row.PublicJSON(), err)
	case protocol.OpIntegrationCredentialRotate:
		var input struct {
			CredentialID       string `json:"credentialId"`
			Value              string `json:"value"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid integration_credential_rotate input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixIntegrationCredential, input.CredentialID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "credentialId is invalid", false)
		}
		row, err := s.integrations.Rotate(req.OwnerID, input.CredentialID, input.Value, input.ExpectedGeneration, now)
		return integrationMutation("Integration credential rotated", row.PublicJSON(), err)
	case protocol.OpIntegrationCredentialDelete:
		var input struct {
			CredentialID       string `json:"credentialId"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid integration_credential_delete input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixIntegrationCredential, input.CredentialID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "credentialId is invalid", false)
		}
		if err := s.integrations.Delete(req.OwnerID, input.CredentialID, input.ExpectedGeneration); err != nil {
			return integrationFail(err)
		}
		return protocol.Success("Integration credential deleted", map[string]any{"id": input.CredentialID, "deleted": true})
	case protocol.OpTypesafeStatus:
		configured := false
		rows, err := s.integrations.List(req.OwnerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		for _, row := range rows {
			if row.Integration == "typesafe" && row.Status == "ACTIVE" {
				configured = true
				break
			}
		}
		return protocol.Success("TypeSafe status", map[string]any{
			"configured": configured,
			"enabled":    true,
			"endpoint":   typesafe.DefaultEndpoint,
			"model":      typesafe.DefaultModel,
		})
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

func integrationMutation(message string, data map[string]any, err error) protocol.ToolResult {
	if err != nil {
		return integrationFail(err)
	}
	return protocol.Success(message, data)
}

func integrationFail(err error) protocol.ToolResult {
	if errors.Is(err, integrations.ErrNotFound) {
		return protocol.Fail(protocol.ErrorNotFound, "Integration credential not found", false)
	}
	if errors.Is(err, integrations.ErrConflict) {
		return protocol.Fail(protocol.ErrorConflict, "This integration credential already exists or changed after you opened it.", false)
	}
	if errors.Is(err, integrations.ErrInvalid) || strings.Contains(err.Error(), "invalid") {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
}
