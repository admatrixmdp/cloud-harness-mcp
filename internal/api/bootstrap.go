package api

import (
	"fmt"
	"os"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
)

// Env is a testable environment lookup. Production uses os.Getenv.
type Env func(string) string

func osEnv(name string) string { return os.Getenv(name) }

func secretFileThenEnv(getenv Env, name string) string {
	if getenv == nil {
		getenv = osEnv
	}
	if file := strings.TrimSpace(getenv(name + "_FILE")); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(raw))
	}
	return strings.TrimSpace(getenv(name))
}

func csvEnv(getenv Env, name, fallback string) []string {
	raw := getenv(name)
	if raw == "" {
		raw = fallback
	}
	out := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func runnerToken(getenv Env) string {
	if token := secretFileThenEnv(getenv, "RUNNER_TOKEN"); token != "" {
		return token
	}
	return secretFileThenEnv(getenv, "RUNNER_SERVICE_TOKEN")
}

// ProductionOptions builds the public HTTP assembly from process env.
// Cloudflare Access never treats an opaque client bearer as identity.
func ProductionOptions(getenv Env) (Options, error) {
	if getenv == nil {
		getenv = osEnv
	}
	mode := auth.Mode(strings.TrimSpace(getenv("AUTH_MODE")))
	if mode == "" {
		mode = auth.ModeOwnerBearer
	}
	if mode != auth.ModeOwnerBearer && mode != auth.ModeCloudflareAccess {
		return Options{}, fmt.Errorf("AUTH_MODE must be owner-bearer or cloudflare-access")
	}
	opts := Options{
		Mode:    mode,
		OwnerID: strings.TrimSpace(getenv("OWNER_ID")),
		Security: SecurityConfig{
			PublicHosts:    csvEnv(getenv, "API_PUBLIC_HOSTS", "localhost,127.0.0.1"),
			AllowedOrigins: csvEnv(getenv, "API_ALLOWED_ORIGINS", ""),
		},
	}
	if url := strings.TrimSpace(getenv("RUNNER_URL")); url != "" {
		opts.Runner = &mcp.RunnerClient{
			BaseURL:      url,
			ServiceToken: runnerToken(getenv),
			OwnerID:      opts.OwnerID,
		}
	}
	switch mode {
	case auth.ModeCloudflareAccess:
		if secretFileThenEnv(getenv, "MCP_BEARER_TOKEN") != "" {
			return Options{}, fmt.Errorf("owner bearer token is forbidden in cloudflare-access mode")
		}
		issuer := strings.TrimSpace(getenv("CLOUDFLARE_ACCESS_ISSUER"))
		audience := strings.TrimSpace(getenv("CLOUDFLARE_ACCESS_AUDIENCE"))
		jwks := strings.TrimSpace(getenv("CLOUDFLARE_ACCESS_JWKS_URL"))
		if issuer == "" || audience == "" || jwks == "" {
			return Options{}, fmt.Errorf("CLOUDFLARE_ACCESS_ISSUER, CLOUDFLARE_ACCESS_AUDIENCE, and CLOUDFLARE_ACCESS_JWKS_URL are required in cloudflare-access mode")
		}
		if !strings.HasPrefix(issuer, "https://") || !strings.HasPrefix(jwks, "https://") {
			return Options{}, fmt.Errorf("Cloudflare Access issuer and JWKS URL must be https")
		}
		opts.AccessVerifier = auth.NewAccessVerifier(auth.AccessConfig{
			Issuer: issuer, Audience: audience, JWKSURL: jwks,
		}, nil, nil)
	default:
		if getenv("CLOUDFLARE_ACCESS_ISSUER") != "" || getenv("CLOUDFLARE_ACCESS_AUDIENCE") != "" || getenv("CLOUDFLARE_ACCESS_JWKS_URL") != "" {
			return Options{}, fmt.Errorf("Cloudflare Access settings are forbidden in owner-bearer mode")
		}
		opts.BearerToken = secretFileThenEnv(getenv, "MCP_BEARER_TOKEN")
		if opts.BearerToken == "" {
			return Options{}, fmt.Errorf("MCP_BEARER_TOKEN is required in owner-bearer mode")
		}
	}
	enabled := strings.TrimSpace(strings.ToLower(getenv("API_KEY_AUTH_ENABLED")))
	opts.APIKeyAuthEnabled = enabled == "true" || enabled == "1"
	opts.APIKeyGatewayPublicURL = strings.TrimSpace(getenv("API_KEY_GATEWAY_PUBLIC_URL"))
	return opts, nil
}
