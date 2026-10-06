package runner

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

type apiKeyRPC struct {
	Version   int             `json:"version"`
	Principal json.RawMessage `json:"principal"`
	Operation string          `json:"operation"`
	Input     json.RawMessage `json:"input"`
	APIKey    string          `json:"apiKey"`
}

func handleAPIKeys(w http.ResponseWriter, r *http.Request, svc *Service) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req apiKeyRPC
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeResult(w, http.StatusBadRequest, protocol.Fail(protocol.ErrorInvalidInput, "invalid API key request", false))
		return
	}
	if svc.apiKeys == nil {
		writeResult(w, http.StatusServiceUnavailable, protocol.Fail(protocol.ErrorUnavailable, "API key service unavailable", true))
		return
	}
	if strings.TrimSpace(req.APIKey) != "" {
		if req.Version != 1 {
			writeJSONRaw(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "authentication_failed"})
			return
		}
		status, body := svc.authenticateAPIKey(req.APIKey)
		writeJSONRaw(w, status, body)
		return
	}
	if req.Version != 1 {
		writeResult(w, http.StatusBadRequest, protocol.Fail(protocol.ErrorInvalidInput, "invalid API key request", false))
		return
	}
	status, body := svc.manageAPIKeys(req)
	writeJSONRaw(w, status, body)
}

func writeJSONRaw(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Service) authenticateAPIKey(apiKey string) (int, any) {
	failed := map[string]any{"ok": false, "error": "authentication_failed"}
	if s.apiKeys == nil {
		return http.StatusUnauthorized, failed
	}
	id, ok := s.apiKeys.VerifyAPIKey(apiKey, time.Now())
	if !ok {
		return http.StatusUnauthorized, failed
	}
	rec, found := s.apiKeys.GetAPIKeyByID(id, time.Now())
	if !found {
		return http.StatusUnauthorized, failed
	}
	return http.StatusOK, map[string]any{
		"ok":   true,
		"data": map[string]any{"principal": principalFromOwner(rec.PrincipalID), "keyId": rec.ID},
	}
}

func (s *Service) manageAPIKeys(req apiKeyRPC) (int, any) {
	if s.apiKeys == nil {
		return http.StatusServiceUnavailable, protocol.Fail(protocol.ErrorUnavailable, "API key service unavailable", true)
	}
	owner := protocol.PrincipalOwnerID(protocol.RunnerRequest{Version: 1, Principal: req.Principal})
	if owner == "" {
		return http.StatusUnauthorized, protocol.Fail(protocol.ErrorAuthenticationFailed, "authentication failed", false)
	}
	now := time.Now()
	switch req.Operation {
	case "api_key_list":
		rows, err := s.apiKeys.ListAPIKeys(owner, now)
		if err != nil {
			return http.StatusServiceUnavailable, protocol.Fail(protocol.ErrorUnavailable, "API key service unavailable", true)
		}
		keys := make([]map[string]any, 0, len(rows))
		for _, rec := range rows {
			keys = append(keys, rec.PublicJSON())
		}
		return http.StatusOK, map[string]any{"ok": true, "operation": req.Operation, "data": map[string]any{"keys": keys}, "truncated": false}
	case "api_key_create":
		var input struct {
			Name          string `json:"name"`
			ExpiresInDays int    `json:"expiresInDays"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return http.StatusBadRequest, protocol.Fail(protocol.ErrorInvalidInput, "invalid API key request", false)
		}
		rec, plaintext, err := s.apiKeys.CreateAPIKey(owner, input.Name, input.ExpiresInDays, now)
		if err != nil {
			if strings.Contains(err.Error(), "active API key limit reached") {
				return http.StatusTooManyRequests, protocol.Fail(protocol.ErrorLimitExceeded, "active API key limit reached", false)
			}
			return http.StatusBadRequest, protocol.Fail(protocol.ErrorInvalidInput, "invalid API key request", false)
		}
		s.auditAPIKey(owner, "api_key.created", rec)
		return http.StatusOK, map[string]any{
			"ok": true, "operation": req.Operation, "truncated": false,
			"data": map[string]any{"key": rec.PublicJSON(), "apiKey": plaintext},
		}
	case "api_key_revoke":
		var input struct {
			KeyID              string `json:"keyId"`
			ExpectedGeneration int    `json:"expectedGeneration"`
		}
		if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidAPIKeyID(input.KeyID) || input.ExpectedGeneration < 1 {
			return http.StatusBadRequest, protocol.Fail(protocol.ErrorInvalidInput, "invalid API key request", false)
		}
		rec, ok := s.apiKeys.RevokeAPIKey(owner, input.KeyID, input.ExpectedGeneration, now)
		if !ok {
			return http.StatusConflict, protocol.Fail(protocol.ErrorConflict, "resource generation changed or resource is unavailable", false)
		}
		s.auditAPIKey(owner, "api_key.revoked", rec)
		return http.StatusOK, map[string]any{"ok": true, "operation": req.Operation, "truncated": false, "data": map[string]any{"key": rec.PublicJSON()}}
	default:
		return http.StatusBadRequest, protocol.Fail(protocol.ErrorInvalidInput, "unknown operation", false)
	}
}

func principalFromOwner(owner string) map[string]any {
	if issuer, subject, ok := strings.Cut(owner, "\x00"); ok && issuer != "" && subject != "" {
		return map[string]any{"kind": "external", "issuer": issuer, "subject": subject}
	}
	return map[string]any{"kind": "owner", "ownerId": owner}
}

func (s *Service) auditAPIKey(owner, action string, rec store.APIKeyRecord) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Record(owner, action, "api_key", rec.ID, rec.Generation, map[string]any{
		"expiresAt": rec.ExpiresAt.UnixMilli(),
	})
}
