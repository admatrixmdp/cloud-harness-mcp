package gateway

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

const maxURLLength = 2048

var unsafeHostSuffixes = []string{
	".localhost", ".local", ".internal", ".home", ".lan", ".corp", ".test", ".invalid", ".example", ".arpa",
}

// EndpointOptions is the SSRF policy for a downstream MCP URL.
type EndpointOptions struct {
	AllowInsecureHTTP     bool
	AllowPrivateEndpoints bool
}

// ValidatedEndpoint is a credential-free URL that passed the policy.
type ValidatedEndpoint struct {
	URL *url.URL
}

// ValidateEndpoint checks a downstream MCP URL. Errors never echo the raw URL.
func ValidateEndpoint(raw string, opts EndpointOptions) (ValidatedEndpoint, error) {
	if raw == "" || len(raw) > maxURLLength {
		return ValidatedEndpoint{}, fmt.Errorf("endpoint URL must be a non-empty string of at most %d characters", maxURLLength)
	}
	if strings.Contains(raw, `\`) || strings.Contains(strings.ToLower(raw), "%2e") || strings.Contains(strings.ToLower(raw), "%2f") || strings.Contains(strings.ToLower(raw), "%5c") {
		return ValidatedEndpoint{}, fmt.Errorf("endpoint URL must not contain backslashes or encoded path separators")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ValidatedEndpoint{}, fmt.Errorf("endpoint is not a valid absolute URL")
	}
	if parsed.User != nil {
		return ValidatedEndpoint{}, fmt.Errorf("endpoint URL must not embed credentials")
	}
	if parsed.RawQuery != "" {
		return ValidatedEndpoint{}, fmt.Errorf("endpoint URL must not contain a query string")
	}
	if parsed.Fragment != "" {
		return ValidatedEndpoint{}, fmt.Errorf("endpoint URL must not contain a fragment")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return ValidatedEndpoint{}, fmt.Errorf("endpoint URL must use https")
	}
	if parsed.Scheme == "http" && !opts.AllowInsecureHTTP {
		return ValidatedEndpoint{}, fmt.Errorf("cleartext http endpoints are refused unless the insecure http opt-in is enabled")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if ip := net.ParseIP(host); ip != nil {
		if !opts.AllowPrivateEndpoints && unsafeAddress(ip) {
			return ValidatedEndpoint{}, fmt.Errorf("endpoint resolves to a private, loopback, link-local, or metadata address")
		}
		if alwaysBlocked(ip) {
			return ValidatedEndpoint{}, fmt.Errorf("endpoint resolves to a link-local or metadata address, which is always refused")
		}
		return ValidatedEndpoint{URL: parsed}, nil
	}
	if unsafeHostname(host) {
		return ValidatedEndpoint{}, fmt.Errorf("endpoint hostname is not a public DNS name")
	}
	return ValidatedEndpoint{URL: parsed}, nil
}

func unsafeHostname(host string) bool {
	if host == "" || host == "localhost" || host == "metadata.google.internal" {
		return true
	}
	for _, suffix := range unsafeHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return !strings.Contains(host, ".")
}

func unsafeAddress(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

func alwaysBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// IsConfiguredEndpoint reports whether requestUrl is the exact origin+path of endpoint.
func IsConfiguredEndpoint(requestURL string, endpoint *url.URL) bool {
	if endpoint == nil {
		return false
	}
	u, err := url.Parse(requestURL)
	if err != nil {
		return false
	}
	return u.Scheme == endpoint.Scheme && strings.EqualFold(u.Host, endpoint.Host) && u.Path == endpoint.Path
}
