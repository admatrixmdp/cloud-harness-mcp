package gateway

import (
	"context"
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
	// Resolve is a test seam. Production uses net.LookupIP.
	Resolve func(host string) ([]net.IP, error)
}

// ValidatedEndpoint is a credential-free URL that passed the policy, plus the
// addresses the transport must pin so a rebinding resolver cannot redirect.
type ValidatedEndpoint struct {
	URL       *url.URL
	Addresses []net.IP
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
	var addresses []net.IP
	if ip := net.ParseIP(host); ip != nil {
		addresses = []net.IP{ip}
	} else {
		if unsafeHostname(host) {
			return ValidatedEndpoint{}, fmt.Errorf("endpoint hostname is not a public DNS name")
		}
		lookup := opts.Resolve
		if lookup == nil {
			lookup = net.LookupIP
		}
		resolved, err := lookup(host)
		if err != nil || len(resolved) == 0 {
			return ValidatedEndpoint{}, fmt.Errorf("endpoint hostname could not be resolved")
		}
		addresses = resolved
	}
	for _, ip := range addresses {
		if ip == nil {
			return ValidatedEndpoint{}, fmt.Errorf("endpoint resolved to an invalid address")
		}
		if !opts.AllowPrivateEndpoints && unsafeAddress(ip) {
			return ValidatedEndpoint{}, fmt.Errorf("endpoint resolves to a private, loopback, link-local, or metadata address")
		}
		if alwaysBlocked(ip) {
			return ValidatedEndpoint{}, fmt.Errorf("endpoint resolves to a link-local or metadata address, which is always refused")
		}
	}
	return ValidatedEndpoint{URL: parsed, Addresses: addresses}, nil
}

// PinnedDialContext dials only the addresses validation returned. A later DNS
// answer that points at a private host cannot steal a credentialed request.
func PinnedDialContext(addresses []net.IP) func(ctx context.Context, network, addr string) (net.Conn, error) {
	pinned := append([]net.IP(nil), addresses...)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if len(pinned) == 0 {
			return nil, fmt.Errorf("no validated address to pin")
		}
		var last error
		d := net.Dialer{}
		for _, ip := range pinned {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			last = fmt.Errorf("no validated address to pin")
		}
		return nil, last
	}
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
