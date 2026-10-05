package git

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// ValidateRepositoryURL enforces credential-free HTTPS remotes on port 443
// against an allowlist. It does not perform DNS; ResolveForbidden is separate
// so unit tests do not need network.
func ValidateRepositoryURL(raw string, allowedHosts []string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%s: repositoryUrl must be a valid HTTPS URL", protocol.ErrorInvalidInput)
	}
	if parsed.Scheme != "https" || parsed.User != nil || (parsed.Port() != "" && parsed.Port() != "443") {
		return nil, fmt.Errorf("%s: only credential-free HTTPS repository URLs on port 443 are allowed", protocol.ErrorInvalidInput)
	}
	host := strings.ToLower(parsed.Hostname())
	if !hostAllowed(host, allowedHosts) {
		return nil, fmt.Errorf("%s: repository host is not allowlisted", protocol.ErrorForbidden)
	}
	return parsed, nil
}

func hostAllowed(host string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(host, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

// AddressForbidden reports whether addr is loopback, link-local, or private.
func AddressForbidden(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
