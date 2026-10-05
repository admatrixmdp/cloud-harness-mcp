package protocol

import (
	"strings"
	"unicode"
)

// Gateway meta-tool names. Downstream tools are never aggregated into tools/list.
const (
	GatewayToolSearch      = "search"
	GatewayToolInspect     = "inspect"
	GatewayToolExecute     = "execute"
	GatewayToolPermissions = "permissions"
	GatewayToolStatus      = "status"
)

// GatewayTools is the constant /mcp-gateway tool set.
var GatewayTools = []string{
	GatewayToolSearch,
	GatewayToolInspect,
	GatewayToolExecute,
	GatewayToolPermissions,
	GatewayToolStatus,
}

const (
	PrefixMCPServer = "mcps"
	PrefixMCPTool   = "mcpt"
	PrefixMCPTrace  = "mcpg"
)

// GatewayTransport is a supported downstream MCP transport.
type GatewayTransport string

const (
	GatewayTransportStreamableHTTP GatewayTransport = "streamable-http"
	GatewayTransportSSE            GatewayTransport = "sse"
)

// GatewayPermission is allow or deny.
type GatewayPermission string

const (
	GatewayAllow GatewayPermission = "allow"
	GatewayDeny  GatewayPermission = "deny"
)

// QualifiedToolName returns <server>.<upstream-tool>.
func QualifiedToolName(serverName, toolName string) string {
	return serverName + "." + toolName
}

func validGatewayServerName(name string) bool {
	if len(name) < 1 || len(name) > 63 {
		return false
	}
	c0 := name[0]
	if !((c0 >= 'a' && c0 <= 'z') || (c0 >= '0' && c0 <= '9')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validGatewayToolName(name string) bool {
	if len(name) < 1 || len(name) > 120 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_' || c == '.' || c == '-'
		if c > 127 {
			return false
		}
		if !ok {
			return false
		}
	}
	return true
}

// ValidQualifiedToolName reports whether value is <server>.<tool>.
func ValidQualifiedToolName(value string) bool {
	if len(value) == 0 || len(value) > 190 {
		return false
	}
	sep := strings.IndexByte(value, '.')
	if sep <= 0 || sep == len(value)-1 {
		return false
	}
	return validGatewayServerName(value[:sep]) && validGatewayToolName(value[sep+1:])
}
