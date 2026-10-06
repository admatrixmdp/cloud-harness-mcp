package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

var apiKeyMetadataKeys = []string{"id", "name", "displayPrefix", "state", "generation", "createdAt", "expiresAt", "lastUsedAt", "revokedAt"}

func registerDashboardAPIKeys(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("GET /api/v1/api-keys", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyAPIKeys(w, r, opts, "api_key_list", map[string]any{})
	})))
	mux.Handle("POST /api/v1/api-keys", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		if !validAPIKeyCreate(w, body) {
			return
		}
		if !opts.APIKeyAuthEnabled {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error":   "unavailable",
				"message": "API key authentication is not enabled.",
			})
			return
		}
		proxyAPIKeys(w, r, opts, "api_key_create", body)
	})))))
	mux.Handle("DELETE /api/v1/api-keys/{keyId}", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := decodeMutation(w, r)
		if !ok {
			return
		}
		id := r.PathValue("keyId")
		if !protocol.ValidAPIKeyID(id) {
			writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
			return
		}
		body["keyId"] = id
		proxyAPIKeys(w, r, opts, "api_key_revoke", body)
	})))))
}

func validAPIKeyCreate(w http.ResponseWriter, body map[string]any) bool {
	name, _ := body["name"].(string)
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return false
	}
	body["name"] = name
	days, ok := jsonInt(body["expiresInDays"])
	if !ok || days < 1 || days > protocol.APIKeyMaxExpiryDays {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return false
	}
	return true
}

func jsonInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

func proxyAPIKeys(w http.ResponseWriter, r *http.Request, opts Options, operation string, input map[string]any) {
	if opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":   "unavailable",
			"message": "API key authentication is not enabled.",
		})
		return
	}
	raw, err := json.Marshal(input)
	if err != nil {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return
	}
	result := opts.Runner.CallApiKeys(r.Context(), operation, raw)
	if !result.OK {
		writeAPIKeyFail(w, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": projectAPIKey(operation, result.Data, opts), "truncated": result.Truncated})
}

func projectAPIKey(operation string, data any, opts Options) map[string]any {
	obj, _ := data.(map[string]any)
	if obj == nil {
		obj = map[string]any{}
	}
	switch operation {
	case "api_key_list":
		readiness := map[string]any{"ready": false}
		if opts.APIKeyAuthEnabled {
			readiness = map[string]any{"ready": true, "publicUrl": opts.APIKeyGatewayPublicURL}
		}
		return map[string]any{
			"keys":      projectObjects(obj["keys"], apiKeyMetadataKeys...),
			"readiness": readiness,
		}
	case "api_key_create":
		out := map[string]any{"key": pickKeys(asObject(obj["key"]), apiKeyMetadataKeys...)}
		if apiKey, ok := obj["apiKey"].(string); ok && protocol.ValidAPIKeyValue(apiKey) {
			out["apiKey"] = apiKey
		}
		return out
	default:
		return map[string]any{"key": pickKeys(asObject(obj["key"]), apiKeyMetadataKeys...)}
	}
}

func writeAPIKeyFail(w http.ResponseWriter, result protocol.ToolResult) {
	code := protocol.ErrorUnavailable
	if result.Error != nil && result.Error.Code != "" {
		code = result.Error.Code
	}
	status := http.StatusServiceUnavailable
	message := "API key authentication is not enabled."
	switch code {
	case protocol.ErrorConflict:
		status = http.StatusConflict
		message = "This API key changed after you opened it."
	case protocol.ErrorLimitExceeded:
		status = http.StatusTooManyRequests
		if result.Message != "" {
			message = result.Message
		}
	case protocol.ErrorInvalidInput:
		status = http.StatusBadRequest
		message = "The request could not be processed."
	case protocol.ErrorAuthenticationFailed:
		status = http.StatusUnauthorized
		message = "Your dashboard session ended."
	default:
		if result.Message != "" && code != protocol.ErrorInternal {
			message = result.Message
		}
	}
	writeJSON(w, status, map[string]any{"error": strings.ToLower(string(code)), "message": message})
}
