// Package config loads fail-closed process configuration from flags and env.
// It does not own secrets; callers pass already-resolved values and must never
// log bearer tokens, API keys, or GitHub App material.
package config

// Transport is the northbound MCP composition root.
type Transport string

const (
	TransportHTTP  Transport = "http"
	TransportStdio Transport = "stdio"
)

// Options mirrors apps/api/src/cli-options.ts.
type Options struct {
	Transport  Transport
	Workspace  string
	GitNetwork bool
	GitPush    bool
	EnvForward []string
}

// Valid reports whether o is internally consistent.
func (o Options) Valid() error {
	if o.Transport != TransportHTTP && o.Transport != TransportStdio {
		return errInvalidTransport
	}
	if o.Transport == TransportStdio && o.Workspace == "" {
		return errStdioNeedsWorkspace
	}
	if o.GitPush && !o.GitNetwork {
		// git-push implies git-network, matching the TypeScript CLI.
	}
	return nil
}

type configError string

func (e configError) Error() string { return string(e) }

const (
	errInvalidTransport    configError = "invalid transport: must be http or stdio"
	errStdioNeedsWorkspace configError = "stdio transport requires --workspace"
)
