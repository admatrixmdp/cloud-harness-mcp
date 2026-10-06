package runner

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/githubapp"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// GitHubVerifier looks up a live GitHub App installation. Tests inject a stub.
type GitHubVerifier interface {
	VerifyInstallation(installationID string) (githubapp.Verified, error)
}

func (s *Service) WithGitHub(store *githubapp.Store, verifier GitHubVerifier) *Service {
	s.github = store
	s.githubVerify = verifier
	return s
}

func (s *Service) githubDashboard(req protocol.RunnerRequest) protocol.ToolResult {
	switch req.Operation {
	case protocol.OpGitHubStatus:
		return s.githubStatus(req.OwnerID)
	case protocol.OpGitHubSetupBegin:
		return s.githubSetupBegin(req)
	case protocol.OpGitHubSetupComplete:
		return s.githubSetupComplete(req)
	case protocol.OpGitHubReconcile:
		return s.githubReconcile(req)
	case protocol.OpGitHubDisconnect:
		return s.githubDisconnect(req)
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown dashboard operation", false)
	}
}

func (s *Service) githubStatus(ownerID string) protocol.ToolResult {
	installations := []map[string]any{}
	repos := []map[string]any{}
	var installation any
	if s.github != nil {
		rows, err := s.github.ListInstallations(ownerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		for _, row := range rows {
			installations = append(installations, row.PublicJSON())
		}
		if first, err := s.github.GetInstallation(ownerID, ""); err == nil && first != nil {
			installation = first.PublicJSON()
		}
		grants, err := s.github.ListRepositoryGrants(ownerID, "")
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		for _, grant := range grants {
			repos = append(repos, grant.PublicJSON())
		}
	}
	if installation == nil {
		installation = nil
	}
	return protocol.Success("GitHub authorization status", map[string]any{
		"configured":    s.cfg.GitHubApp.AppSlug != "",
		"installations": installations,
		"installation":  installation,
		"repositories":  repos,
	})
}

func (s *Service) githubSetupBegin(req protocol.RunnerRequest) protocol.ToolResult {
	if s.github == nil || s.cfg.GitHubApp.AppSlug == "" || s.cfg.GitHubApp.AppID == "" {
		return protocol.Fail(protocol.ErrorUnavailable, "GitHub App setup is not configured", true)
	}
	var input struct {
		ExpectedAccountID string `json:"expectedAccountId"`
	}
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid github_setup_begin input", false)
		}
	}
	if input.ExpectedAccountID != "" && len(input.ExpectedAccountID) > 100 {
		return protocol.Fail(protocol.ErrorInvalidInput, "expectedAccountId is invalid", false)
	}
	state, expiresAt, err := s.github.CreateSetup(req.OwnerID, s.cfg.GitHubApp.AppID, input.ExpectedAccountID, 10*60_000)
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	return protocol.Success("GitHub setup started", map[string]any{
		"state":     state,
		"expiresAt": expiresAt,
		"url":       "https://github.com/apps/" + url.PathEscape(s.cfg.GitHubApp.AppSlug) + "/installations/new?state=" + url.QueryEscape(state),
	})
}

func (s *Service) githubSetupComplete(req protocol.RunnerRequest) protocol.ToolResult {
	if s.github == nil || s.githubVerify == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "GitHub App setup is not configured", true)
	}
	var input struct {
		State          string `json:"state"`
		InstallationID string `json:"installationId"`
	}
	if err := json.Unmarshal(req.Input, &input); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid github_setup_complete input", false)
	}
	if len(input.State) < 32 || len(input.State) > 128 || strings.TrimSpace(input.InstallationID) == "" || len(input.InstallationID) > 100 {
		return protocol.Fail(protocol.ErrorInvalidInput, "GitHub installation setup is invalid or expired", false)
	}
	setup, err := s.github.ConsumeSetup(input.State, req.OwnerID)
	if err != nil {
		if errors.Is(err, githubapp.ErrInvalidSetup) {
			return protocol.Fail(protocol.ErrorForbidden, "GitHub installation setup is invalid or expired", false)
		}
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	verified, err := s.githubVerify.VerifyInstallation(input.InstallationID)
	if err != nil {
		return githubVerifyError(err)
	}
	if !githubapp.SameID(setup.ExpectedAppID, verified.AppID) ||
		!githubapp.SameID(input.InstallationID, verified.InstallationID) ||
		(setup.ExpectedAccountID != "" && !githubapp.SameID(setup.ExpectedAccountID, verified.AccountID)) {
		return protocol.Fail(protocol.ErrorForbidden, "GitHub installation setup is invalid or expired", false)
	}
	rec, err := s.github.ReplaceVerified(req.OwnerID, verified, time.Now().UnixMilli())
	if err != nil {
		if errors.Is(err, githubapp.ErrConflict) {
			return protocol.Fail(protocol.ErrorConflict, "GitHub installation is already bound", false)
		}
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	s.recordGitHubAudit(req.OwnerID, "github.bound", rec.InstallationID, rec.Generation, map[string]any{"accountLogin": rec.AccountLogin})
	return githubStatusMessage(s.githubStatus(req.OwnerID), "GitHub installation connected")
}

func (s *Service) githubReconcile(req protocol.RunnerRequest) protocol.ToolResult {
	if s.github == nil || s.githubVerify == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "GitHub App setup is not configured", true)
	}
	var input struct {
		InstallationID string `json:"installationId"`
	}
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid github_reconcile input", false)
		}
	}
	var list []githubapp.Installation
	if input.InstallationID != "" {
		if len(input.InstallationID) > 100 {
			return protocol.Fail(protocol.ErrorInvalidInput, "installationId is invalid", false)
		}
		row, err := s.github.GetInstallation(req.OwnerID, input.InstallationID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		if row != nil {
			list = []githubapp.Installation{*row}
		}
	} else {
		rows, err := s.github.ListInstallations(req.OwnerID)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		list = rows
	}
	if len(list) == 0 {
		return s.githubStatus(req.OwnerID)
	}
	for _, installation := range list {
		if installation.Status == "uninstalled" {
			continue
		}
		verified, err := s.githubVerify.VerifyInstallation(installation.InstallationID)
		if err != nil {
			if isNotFound(err) {
				if rec, markErr := s.github.MarkUninstalled(req.OwnerID, installation.InstallationID, time.Now().UnixMilli()); markErr == nil && rec != nil {
					s.recordGitHubAudit(req.OwnerID, "github.uninstalled", rec.InstallationID, rec.Generation, map[string]any{"status": rec.Status})
				}
				continue
			}
			return githubVerifyError(err)
		}
		if !githubapp.SameID(installation.AppID, verified.AppID) ||
			!githubapp.SameID(installation.AccountID, verified.AccountID) ||
			!githubapp.SameID(installation.InstallationID, verified.InstallationID) {
			return protocol.Fail(protocol.ErrorConflict, "GitHub installation identity changed during reconciliation", false)
		}
		rec, err := s.github.ReplaceVerified(req.OwnerID, verified, time.Now().UnixMilli())
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
		}
		s.recordGitHubAudit(req.OwnerID, "github.reconciled", rec.InstallationID, rec.Generation, map[string]any{"status": rec.Status})
	}
	return githubStatusMessage(s.githubStatus(req.OwnerID), "GitHub authorization reconciled")
}

func (s *Service) githubDisconnect(req protocol.RunnerRequest) protocol.ToolResult {
	if s.github == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "GitHub App setup is not configured", true)
	}
	var input struct {
		InstallationID string `json:"installationId"`
	}
	if err := json.Unmarshal(req.Input, &input); err != nil || strings.TrimSpace(input.InstallationID) == "" || len(input.InstallationID) > 100 {
		return protocol.Fail(protocol.ErrorInvalidInput, "installationId is required", false)
	}
	rec, ok, err := s.github.RemoveInstallation(req.OwnerID, input.InstallationID, time.Now().UnixMilli())
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), true)
	}
	if !ok {
		return protocol.Fail(protocol.ErrorNotFound, "GitHub installation not found", false)
	}
	s.recordGitHubAudit(req.OwnerID, "github.disconnected", rec.InstallationID, rec.Generation, map[string]any{"accountLogin": rec.AccountLogin})
	return githubStatusMessage(s.githubStatus(req.OwnerID), "GitHub installation disconnected")
}

func githubStatusMessage(result protocol.ToolResult, message string) protocol.ToolResult {
	if result.OK {
		result.Message = message
	}
	return result
}

func (s *Service) recordGitHubAudit(ownerID, action, subjectID string, generation int, details map[string]any) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Record(ownerID, action, "github_installation", subjectID, generation, details)
}

func githubVerifyError(err error) protocol.ToolResult {
	msg := err.Error()
	switch {
	case isNotFound(err):
		return protocol.Fail(protocol.ErrorNotFound, "GitHub installation not found", false)
	case strings.Contains(msg, "TIMEOUT") || strings.Contains(strings.ToLower(msg), "timed out"):
		return protocol.Fail(protocol.ErrorTimeout, "GitHub installation verification timed out", true)
	case strings.Contains(msg, "LIMIT_EXCEEDED"):
		return protocol.Fail(protocol.ErrorLimitExceeded, "GitHub repository verification exceeded its completeness bound", false)
	default:
		return protocol.Fail(protocol.ErrorUnavailable, "GitHub installation verification failed", true)
	}
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "NOT_FOUND") || strings.Contains(strings.ToLower(err.Error()), "not found")
}
