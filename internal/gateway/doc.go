// Package gateway is the /mcp-gateway five-tool surface.
//
// Constant tools: search, inspect, execute, permissions, status.
// Downstream tools are never listed. The API owns the outbound MCP client
// socket; the runner owns registry, policy, traces, and secret resolution.
package gateway

// Tools is the constant gateway tool set.
var Tools = []string{"search", "inspect", "execute", "permissions", "status"}
