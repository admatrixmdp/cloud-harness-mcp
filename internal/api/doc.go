// Package api is the public HTTP assembly (today apps/api).
//
// It owns MCP negotiation, request security, dashboard BFF, and translation
// to a versioned private runner RPC. It must not receive a Docker socket,
// host job mounts, or GitHub App credentials.
package api
