package api

import (
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/apps/api"
	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
)

const (
	themeCookieName       = "ch-dashboard-theme"
	displayNameCookieName = "ch-dashboard-display-name"
	preferenceMaxAge      = 31536000
)

var dashboardAssets = map[string]string{
	"dashboard.css":       "text/css; charset=utf-8",
	"dashboard-api.js":    "text/javascript; charset=utf-8",
	"dashboard-render.js": "text/javascript; charset=utf-8",
	"dashboard-pages.js":  "text/javascript; charset=utf-8",
	"dashboard.js":        "text/javascript; charset=utf-8",
}

var displayNamePattern = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._'-]{0,63}$`)

var dashboardShellPaths = []string{
	"/",
	"/workspaces",
	"/workspaces/{workspaceId}",
	"/workspaces/{workspaceId}/summary",
	"/workspaces/{workspaceId}/agents",
	"/workspaces/{workspaceId}/runtime",
	"/workspaces/{workspaceId}/files",
	"/workspaces/{workspaceId}/git",
	"/workspaces/{workspaceId}/automation",
	"/workspaces/{workspaceId}/deploy",
	"/workspaces/{workspaceId}/artifacts",
	"/workspaces/{workspaceId}/activity",
	"/agents",
	"/agents/{agentId}",
	"/projects",
	"/projects/{projectId}",
	"/secrets",
	"/models",
	"/artifacts",
	"/audit",
	"/api-keys",
	"/knowledge",
	"/knowledge/{id}",
	"/skills",
	"/integrations",
	"/integrations/github",
	"/activity",
	"/approvals",
	"/mcp-servers",
	"/mcp-servers/{serverId}",
	"/settings",
	"/profile",
}

var (
	shellOnce sync.Once
	shells    map[string]string
)

func dashboardShells() map[string]string {
	shellOnce.Do(func() {
		raw, err := fs.ReadFile(apiembed.DashboardFS(), "index.html")
		if err != nil {
			panic("dashboard shell missing: " + err.Error())
		}
		version := apiembed.ServerVersion()
		versioned := strings.ReplaceAll(string(raw), "__CH_VERSION__", version)
		versioned = strings.ReplaceAll(versioned, "__CH_ASSET_VERSION__", url.PathEscape(version))
		shells = map[string]string{
			"system": versioned,
			"light":  strings.Replace(versioned, `<html lang="en">`, `<html lang="en" data-theme="light">`, 1),
			"dark":   strings.Replace(versioned, `<html lang="en">`, `<html lang="en" data-theme="dark">`, 1),
		}
	})
	return shells
}

func registerDashboardAssets(mux *http.ServeMux) {
	mux.HandleFunc("GET /assets/{version}/{asset}", serveVersionedAsset)
	for name := range dashboardAssets {
		asset := name
		mux.HandleFunc("GET /assets/"+asset, func(w http.ResponseWriter, _ *http.Request) {
			serveLegacyAsset(w, asset)
		})
	}
	mux.HandleFunc("GET /overview", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})
	mux.HandleFunc("GET /github", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/integrations/github", http.StatusFound)
	})
	mux.HandleFunc("GET /integrations/mcp-servers", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/mcp-servers", http.StatusFound)
	})
	for _, path := range dashboardShellPaths {
		mux.HandleFunc("GET "+path, serveDashboardShell)
	}
}

func serveDashboardShell(w http.ResponseWriter, r *http.Request) {
	theme := forcedTheme(r)
	html := dashboardShells()[theme]
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func serveVersionedAsset(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	asset := r.PathValue("asset")
	if version != apiembed.ServerVersion() {
		http.NotFound(w, r)
		return
	}
	writeDashboardAsset(w, asset, "private, max-age=31536000, immutable")
}

func serveLegacyAsset(w http.ResponseWriter, asset string) {
	writeDashboardAsset(w, asset, "private, no-cache")
}

func writeDashboardAsset(w http.ResponseWriter, asset, cache string) {
	ctype, ok := dashboardAssets[asset]
	if !ok {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	raw, err := fs.ReadFile(apiembed.DashboardFS(), asset)
	if err != nil {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", cache)
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(raw)
}

func forcedTheme(r *http.Request) string {
	value := cookieValue(r, themeCookieName)
	if value == "light" || value == "dark" {
		return value
	}
	return "system"
}

func cookieValue(r *http.Request, name string) string {
	header := r.Header.Get("Cookie")
	if header == "" {
		return ""
	}
	for _, part := range strings.Split(header, ";") {
		index := strings.Index(part, "=")
		if index == -1 {
			continue
		}
		if strings.TrimSpace(part[:index]) != name {
			continue
		}
		return strings.TrimSpace(part[index+1:])
	}
	return ""
}

func preferredDisplayName(r *http.Request) any {
	raw := cookieValue(r, displayNameCookieName)
	if raw == "" {
		return nil
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return nil
	}
	decoded = strings.TrimSpace(decoded)
	if !displayNamePattern.MatchString(decoded) {
		return nil
	}
	return decoded
}

func writeProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session_ended", "message": "Your dashboard session ended."})
		return
	}
	identity := map[string]any{
		"issuer":  id.Issuer,
		"subject": id.Subject,
	}
	if id.Email != "" {
		identity["email"] = id.Email
	}
	if id.Name != "" {
		identity["name"] = id.Name
	}
	var expires any
	if id.ExpiresAt > 0 {
		expires = time.Unix(id.ExpiresAt, 0).UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"identity":         identity,
			"scopes":           []string{},
			"preferences":      map[string]any{"displayName": preferredDisplayName(r)},
			"sessionExpiresAt": expires,
		},
	})
}

func writeServer(w http.ResponseWriter, r *http.Request, opts Options) {
	id, ok := auth.IdentityFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session_ended", "message": "Your dashboard session ended."})
		return
	}
	mode := string(opts.Mode)
	if mode == "" {
		mode = string(auth.ModeOwnerBearer)
	}
	var managed any
	if len(opts.Security.PublicHosts) > 0 {
		managed = "https://" + opts.Security.PublicHosts[0] + "/mcp"
	}
	apiKey := map[string]any{"enabled": false}
	if opts.APIKeyAuthEnabled {
		apiKey = map[string]any{"enabled": true, "endpoint": opts.APIKeyGatewayPublicURL}
	}
	maxBody := opts.MaxBodyBytes
	if maxBody == 0 {
		maxBody = 1_048_576
	}
	timeout := opts.RequestTimeoutMs
	if timeout == 0 {
		timeout = 60_000
	}
	var expires any
	if id.ExpiresAt > 0 {
		expires = time.Unix(id.ExpiresAt, 0).UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"authMode":        mode,
			"managedOAuthUrl": managed,
			"apiKeyGateway":   apiKey,
			"limits":          map[string]any{"maxRequestBytes": maxBody, "requestTimeoutMs": timeout},
			"version":         apiembed.ServerVersion(),
			"session":         map[string]any{"expiresAt": expires, "scopes": []string{}},
			"checkedAt":       time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
}

func writePreferences(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeMutation(w, r)
	if !ok {
		return
	}
	theme, hasTheme := body["theme"].(string)
	displayRaw, hasDisplay := body["displayName"]
	if !hasTheme && !hasDisplay {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "message": "Unsupported dashboard preference."})
		return
	}
	if hasTheme && theme != "system" && theme != "light" && theme != "dark" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "message": "Unsupported dashboard preference."})
		return
	}
	if hasTheme {
		if theme == "system" {
			http.SetCookie(w, preferenceCookie(themeCookieName, "", true))
		} else {
			http.SetCookie(w, preferenceCookie(themeCookieName, theme, false))
		}
	}
	out := map[string]any{}
	if hasTheme {
		out["theme"] = theme
	}
	if hasDisplay {
		var displayName *string
		switch v := displayRaw.(type) {
		case nil:
			displayName = nil
		case string:
			trimmed := strings.TrimSpace(v)
			if trimmed != "" && !displayNamePattern.MatchString(trimmed) {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error":   "invalid_request",
					"message": "Display names may use letters, numbers, spaces, and . _ - ' only (up to 64 characters).",
				})
				return
			}
			if trimmed == "" {
				displayName = nil
			} else {
				displayName = &trimmed
			}
		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "message": "Unsupported dashboard preference."})
			return
		}
		if displayName == nil {
			http.SetCookie(w, preferenceCookie(displayNameCookieName, "", true))
			out["displayName"] = nil
		} else {
			http.SetCookie(w, preferenceCookie(displayNameCookieName, url.PathEscape(*displayName), false))
			out["displayName"] = *displayName
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func preferenceCookie(name, value string, clear bool) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/dashboard",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	if clear {
		c.MaxAge = -1
		c.Expires = time.Unix(0, 0)
	} else {
		c.MaxAge = preferenceMaxAge
	}
	return c
}

func stripDashboard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/dashboard")
		if p == "" {
			p = "/"
		}
		clone := r.Clone(r.Context())
		u := *r.URL
		u.Path = p
		clone.URL = &u
		next.ServeHTTP(w, clone)
	})
}
