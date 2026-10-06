// Package apiembed exposes the API package manifest and dashboard static files
// for the Go port. go:embed cannot walk out of a package, so this file lives
// next to package.json and dashboard/.
package apiembed

import (
	"embed"
	"encoding/json"
	"io/fs"
	"regexp"
)

//go:embed package.json dashboard/index.html dashboard/dashboard.css dashboard/dashboard.js dashboard/dashboard-api.js dashboard/dashboard-pages.js dashboard/dashboard-render.js
var files embed.FS

// Character allowlist for the version string injected into the dashboard shell.
// Matches apps/api/src/version.ts: reject markup, accept release-tooling forms.
var versionAllowlist = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]*$`)

// ServerVersion is the running server version from apps/api/package.json.
func ServerVersion() string {
	raw, err := files.ReadFile("package.json")
	if err != nil {
		return "unknown"
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		return "unknown"
	}
	return NormalizeServerVersion(manifest.Version)
}

// NormalizeServerVersion rejects values that could produce markup in the shell.
func NormalizeServerVersion(value string) string {
	if versionAllowlist.MatchString(value) {
		return value
	}
	return "unknown"
}

// DashboardFS is the dashboard static directory (index.html and assets).
func DashboardFS() fs.FS {
	sub, err := fs.Sub(files, "dashboard")
	if err != nil {
		panic("apiembed: dashboard files missing")
	}
	return sub
}
