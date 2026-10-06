package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

var mutationMethods = map[string]struct{}{
	http.MethodPost: {}, http.MethodPut: {}, http.MethodPatch: {}, http.MethodDelete: {},
}

func dashboardHandler(opts Options, sessions *Sessions) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/session", sessions.bootstrap)
	mux.Handle("GET /api/v1/privilege-grants", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpPrivilegeGrantList, map[string]any{
			"workspaceId": r.URL.Query().Get("workspaceId"),
		})
	})))
	mux.Handle("POST /api/v1/privilege-grants/{grantId}/approve", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpPrivilegeGrantApprove, map[string]any{
			"grantId": r.PathValue("grantId"),
		})
	})))))
	mux.Handle("POST /api/v1/privilege-grants/{grantId}/reject", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyDashboard(w, r, opts.Runner, protocol.OpPrivilegeGrantReject, map[string]any{
			"grantId": r.PathValue("grantId"),
		})
	})))))
	return dashboardSecurity(opts.Security, mux)
}

func dashboardSecurity(cfg SecurityConfig, next http.Handler) http.Handler {
	hosts := map[string]struct{}{}
	for _, h := range cfg.PublicHosts {
		hosts[strings.ToLower(h)] = struct{}{}
	}
	origins := map[string]struct{}{}
	for _, raw := range cfg.AllowedOrigins {
		origins[strings.ToLower(strings.TrimRight(raw, "/"))] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(hosts) > 0 {
			host := hostnameFromHost(r.Host)
			if _, ok := hosts[host]; !ok {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden_host"})
				return
			}
			if raw := r.Header.Get("Origin"); raw != "" {
				if _, ok := origins[strings.ToLower(strings.TrimRight(raw, "/"))]; !ok {
					writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden_origin"})
					return
				}
			} else if _, mut := mutationMethods[r.Method]; mut {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "origin_required"})
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", dashboardCSP)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func requirePrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.IdentityFrom(r.Context()); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session_ended", "message": "Your dashboard session ended."})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, mut := mutationMethods[r.Method]; mut {
			ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
			if ct != "application/json" {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "unsupported_media_type"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func proxyDashboard(w http.ResponseWriter, r *http.Request, runner *mcp.RunnerClient, op protocol.Operation, input map[string]any) {
	if runner == nil {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorUnavailable, "The workspace service is temporarily unavailable.", true))
		return
	}
	if workspace, ok := input["workspaceId"].(string); ok && workspace == "" {
		delete(input, "workspaceId")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return
	}
	result := runner.CallInternal(r.Context(), op, raw)
	if !result.OK {
		writeDashboardFail(w, result)
		return
	}
	data := projectGrant(op, result.Data)
	out := map[string]any{"data": data, "truncated": result.Truncated}
	if result.Cursor != "" {
		out["cursor"] = result.Cursor
	}
	writeJSON(w, http.StatusOK, out)
}

func projectGrant(op protocol.Operation, data any) any {
	obj, _ := data.(map[string]any)
	if obj == nil {
		return map[string]any{}
	}
	switch op {
	case protocol.OpPrivilegeGrantList:
		return map[string]any{"grants": projectGrantList(obj["grants"])}
	case protocol.OpPrivilegeGrantApprove, protocol.OpPrivilegeGrantReject:
		return map[string]any{"grant": pickGrant(obj["grant"])}
	default:
		return obj
	}
}

func projectGrantList(raw any) []map[string]any {
	switch rows := raw.(type) {
	case []map[string]any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, pickGrant(row))
		}
		return out
	case []any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			out = append(out, pickGrant(row))
		}
		return out
	default:
		return []map[string]any{}
	}
}

func pickGrant(raw any) map[string]any {
	obj, _ := raw.(map[string]any)
	if obj == nil {
		return map[string]any{}
	}
	keys := []string{"id", "ownerId", "workspaceId", "command", "cwd", "commandSha256", "status", "createdAt", "expiresAt", "consumedAt"}
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := obj[k]; ok {
			out[k] = v
		}
	}
	return out
}

func writeDashboardFail(w http.ResponseWriter, result protocol.ToolResult) {
	code := protocol.ErrorInternal
	if result.Error != nil && result.Error.Code != "" {
		code = result.Error.Code
	}
	status := http.StatusInternalServerError
	switch code {
	case protocol.ErrorAuthenticationFailed:
		status = http.StatusUnauthorized
	case protocol.ErrorForbidden, protocol.ErrorNotFound:
		status = http.StatusNotFound
	case protocol.ErrorInvalidInput:
		status = http.StatusBadRequest
	case protocol.ErrorConflict:
		status = http.StatusConflict
	case protocol.ErrorExpired:
		status = http.StatusGone
	case protocol.ErrorLimitExceeded:
		status = http.StatusTooManyRequests
	case protocol.ErrorTimeout:
		status = http.StatusGatewayTimeout
	case protocol.ErrorUnavailable, protocol.ErrorDependencyEgressUnavailable:
		status = http.StatusServiceUnavailable
	}
	message := dashboardMessage(code)
	writeJSON(w, status, map[string]any{"error": strings.ToLower(string(code)), "message": message})
}

func dashboardMessage(code protocol.ErrorCode) string {
	switch code {
	case protocol.ErrorAuthenticationFailed:
		return "Your dashboard session ended."
	case protocol.ErrorForbidden, protocol.ErrorNotFound:
		return "Workspace not found or no longer available."
	case protocol.ErrorInvalidInput:
		return "The request could not be processed."
	case protocol.ErrorConflict:
		return "This item changed after you opened it."
	case protocol.ErrorExpired:
		return "Workspace expired."
	case protocol.ErrorLimitExceeded:
		return "Too many requests. Try again later."
	case protocol.ErrorTimeout:
		return "The workspace service took too long to respond."
	case protocol.ErrorUnavailable, protocol.ErrorDependencyEgressUnavailable:
		return "The workspace service is temporarily unavailable."
	default:
		return "The workspace service could not complete the request."
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
