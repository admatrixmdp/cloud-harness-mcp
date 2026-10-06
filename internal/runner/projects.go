package runner

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/metadata"
	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func (s *Service) projectsDashboard(req protocol.RunnerRequest) protocol.ToolResult {
	switch req.Operation {
	case protocol.OpProjectList, protocol.OpProjectCreate, protocol.OpProjectUpdate, protocol.OpProjectDelete,
		protocol.OpEnvironmentList, protocol.OpEnvironmentCreate, protocol.OpEnvironmentUpdate, protocol.OpEnvironmentDelete:
		return s.projectEnvironment(req)
	case protocol.OpSecretList, protocol.OpSecretCreate, protocol.OpSecretRotate, protocol.OpSecretUpdate, protocol.OpSecretDelete, protocol.OpSecretBulkApply,
		protocol.OpGlobalSecretList, protocol.OpGlobalSecretCreate, protocol.OpGlobalSecretRotate, protocol.OpGlobalSecretUpdate, protocol.OpGlobalSecretDelete, protocol.OpGlobalSecretBulkApply:
		return s.secretDashboard(req)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

func (s *Service) projectEnvironment(req protocol.RunnerRequest) protocol.ToolResult {
	if s.metadata == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "project metadata is unavailable", true)
	}
	now := time.Now().UnixMilli()
	switch req.Operation {
	case protocol.OpProjectList:
		rows, err := s.metadata.ListProjects(req.OwnerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.PublicJSON())
		}
		return protocol.Success("Projects listed", map[string]any{"projects": out})
	case protocol.OpProjectCreate:
		var input struct {
			Name               string `json:"name"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid project_create input", false)
		}
		row, err := s.metadata.CreateProject(req.OwnerID, input.Name, input.ExpectedGeneration, now)
		return mutationResult("Project created", row.PublicJSON(), err)
	case protocol.OpProjectUpdate:
		var input struct {
			ProjectID          string `json:"projectId"`
			Name               string `json:"name"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid project_update input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixProject, input.ProjectID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "projectId is invalid", false)
		}
		row, err := s.metadata.UpdateProject(req.OwnerID, input.ProjectID, input.Name, input.ExpectedGeneration, now)
		return mutationResult("Project updated", row.PublicJSON(), err)
	case protocol.OpProjectDelete:
		var input struct {
			ProjectID          string `json:"projectId"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid project_delete input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixProject, input.ProjectID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "projectId is invalid", false)
		}
		row, err := s.metadata.DeleteProject(req.OwnerID, input.ProjectID, input.ExpectedGeneration, now)
		return mutationResult("Project deleted", row.PublicJSON(), err)
	case protocol.OpEnvironmentList:
		var input struct {
			ProjectID string `json:"projectId"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid environment_list input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixProject, input.ProjectID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "projectId is invalid", false)
		}
		rows, err := s.metadata.ListEnvironments(req.OwnerID, input.ProjectID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.PublicJSON())
		}
		return protocol.Success("Environments listed", map[string]any{"environments": out})
	case protocol.OpEnvironmentCreate:
		var input struct {
			ProjectID          string `json:"projectId"`
			Name               string `json:"name"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid environment_create input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixProject, input.ProjectID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "projectId is invalid", false)
		}
		row, err := s.metadata.CreateEnvironment(req.OwnerID, input.ProjectID, input.Name, input.ExpectedGeneration, now)
		return mutationResult("Environment created", row.PublicJSON(), err)
	case protocol.OpEnvironmentUpdate:
		var input struct {
			EnvironmentID      string `json:"environmentId"`
			Name               string `json:"name"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid environment_update input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, input.EnvironmentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
		}
		row, err := s.metadata.UpdateEnvironment(req.OwnerID, input.EnvironmentID, input.Name, input.ExpectedGeneration, now)
		return mutationResult("Environment updated", row.PublicJSON(), err)
	case protocol.OpEnvironmentDelete:
		var input struct {
			EnvironmentID      string `json:"environmentId"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid environment_delete input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, input.EnvironmentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
		}
		row, err := s.metadata.DeleteEnvironment(req.OwnerID, input.EnvironmentID, input.ExpectedGeneration, now)
		return mutationResult("Environment deleted", row.PublicJSON(), err)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

func (s *Service) secretDashboard(req protocol.RunnerRequest) protocol.ToolResult {
	now := time.Now()
	switch req.Operation {
	case protocol.OpSecretList:
		var input struct {
			EnvironmentID string `json:"environmentId"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid secret_list input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, input.EnvironmentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
		}
		secretsOut := []map[string]any{}
		if s.secrets != nil {
			rows, err := s.secrets.ListDashboard(req.OwnerID, input.EnvironmentID)
			if err != nil {
				return protocol.Fail(protocol.ErrorInternal, "secret metadata is unavailable", true)
			}
			secretsOut = secretViews(rows)
		}
		return protocol.Success("Secret references listed", map[string]any{
			"secrets":   secretsOut,
			"readiness": s.secretReadiness(),
		})
	case protocol.OpGlobalSecretList:
		secretsOut := []map[string]any{}
		if s.secrets != nil {
			rows, err := s.secrets.ListGlobal(req.OwnerID)
			if err != nil {
				return protocol.Fail(protocol.ErrorInternal, "secret metadata is unavailable", true)
			}
			secretsOut = secretViews(rows)
		}
		return protocol.Success("Global secrets listed", map[string]any{
			"secrets":   secretsOut,
			"readiness": s.secretReadiness(),
		})
	}
	if s.secrets == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "Secret operations are temporarily unavailable", true)
	}
	switch req.Operation {
	case protocol.OpSecretCreate:
		var input secretWriteInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid secret_create input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, input.EnvironmentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
		}
		desc := ""
		if input.Description != nil {
			desc = *input.Description
		}
		row, err := s.secrets.CreateScoped(req.OwnerID, input.EnvironmentID, input.Name, input.Value, input.ExpectedGeneration, desc, input.Purpose, now)
		return mutationResult("Secret reference created", row.PublicJSON(), err)
	case protocol.OpSecretRotate:
		var input secretWriteInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid secret_rotate input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, input.EnvironmentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
		}
		row, err := s.secrets.Rotate(req.OwnerID, input.EnvironmentID, input.Name, input.Value, input.ExpectedGeneration, input.Description, now)
		return mutationResult("Secret reference rotated", row.PublicJSON(), err)
	case protocol.OpSecretUpdate:
		var input secretWriteInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid secret_update input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, input.EnvironmentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
		}
		row, err := s.secrets.UpdateMetadata(req.OwnerID, input.EnvironmentID, input.Name, input.Description, input.ExpectedGeneration, now)
		return mutationResult("Secret reference updated", row.PublicJSON(), err)
	case protocol.OpSecretDelete:
		var input secretWriteInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid secret_delete input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, input.EnvironmentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
		}
		row, err := s.secrets.Delete(req.OwnerID, input.EnvironmentID, input.Name, input.ExpectedGeneration, now)
		return mutationResult("Secret reference deleted", row.PublicJSON(), err)
	case protocol.OpSecretBulkApply:
		var input struct {
			EnvironmentID string             `json:"environmentId"`
			Items         []secrets.BulkItem `json:"items"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid secret_bulk_apply input", false)
		}
		if !protocol.ValidOpaqueID(protocol.PrefixEnvironment, input.EnvironmentID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
		}
		rows, err := s.secrets.BulkApply(req.OwnerID, input.EnvironmentID, input.Items, now)
		if err != nil {
			return secretFail(err)
		}
		return protocol.Success("Secrets bulk applied", map[string]any{"secrets": secretViews(rows)})
	case protocol.OpGlobalSecretCreate:
		var input secretWriteInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid global_secret_create input", false)
		}
		desc := ""
		if input.Description != nil {
			desc = *input.Description
		}
		row, err := s.secrets.CreateGlobal(req.OwnerID, input.Name, input.Value, input.ExpectedGeneration, desc, input.Purpose, now)
		return mutationResult("Global secret created", row.PublicJSON(), err)
	case protocol.OpGlobalSecretRotate:
		var input secretWriteInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid global_secret_rotate input", false)
		}
		row, err := s.secrets.RotateGlobal(req.OwnerID, input.Name, input.Value, input.ExpectedGeneration, input.Description, now)
		return mutationResult("Global secret rotated", row.PublicJSON(), err)
	case protocol.OpGlobalSecretUpdate:
		var input secretWriteInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid global_secret_update input", false)
		}
		row, err := s.secrets.UpdateGlobalMetadata(req.OwnerID, input.Name, input.Description, input.ExpectedGeneration, now)
		return mutationResult("Global secret updated", row.PublicJSON(), err)
	case protocol.OpGlobalSecretDelete:
		var input secretWriteInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid global_secret_delete input", false)
		}
		row, err := s.secrets.DeleteGlobal(req.OwnerID, input.Name, input.ExpectedGeneration, now)
		return mutationResult("Global secret deleted", row.PublicJSON(), err)
	case protocol.OpGlobalSecretBulkApply:
		var input struct {
			Items []secrets.BulkItem `json:"items"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid global_secret_bulk_apply input", false)
		}
		rows, err := s.secrets.BulkApplyGlobal(req.OwnerID, input.Items, now)
		if err != nil {
			return secretFail(err)
		}
		return protocol.Success("Global secrets bulk applied", map[string]any{"secrets": secretViews(rows)})
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

type secretWriteInput struct {
	EnvironmentID      string  `json:"environmentId"`
	Name               string  `json:"name"`
	Value              string  `json:"value"`
	Description        *string `json:"description"`
	Purpose            string  `json:"purpose"`
	ExpectedGeneration int     `json:"expectedGeneration"`
}

func (s *Service) secretReadiness() map[string]any {
	if s.secrets == nil {
		return map[string]any{"ready": false, "error": "secret keyring is unavailable"}
	}
	return map[string]any{"ready": true}
}

func secretViews(rows []secrets.View) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.PublicJSON())
	}
	return out
}

func mutationResult(message string, data map[string]any, err error) protocol.ToolResult {
	if err != nil {
		return secretFail(err)
	}
	return protocol.Success(message, data)
}

func secretFail(err error) protocol.ToolResult {
	if errors.Is(err, metadata.ErrConflict) || errors.Is(err, secrets.ErrConflict) {
		return protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
	}
	if errors.Is(err, metadata.ErrInvalidName) {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	msg := err.Error()
	if strings.Contains(msg, "secret name") || strings.Contains(msg, "secret value") || strings.Contains(msg, "secret description") || strings.Contains(msg, "secret purpose") || strings.Contains(msg, "bulk") {
		return protocol.Fail(protocol.ErrorInvalidInput, msg, false)
	}
	return protocol.Fail(protocol.ErrorInternal, msg, true)
}
