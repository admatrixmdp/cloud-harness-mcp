package provisioning

import (
	"fmt"
	"net"
	"os"
	"strings"
)

const defaultAllowedHosts = "github.com,api.github.com,objects.githubusercontent.com,raw.githubusercontent.com"

// Config is the dual-homed helper egress proxy. It must not receive secrets
// or publish a host port; Compose keeps those boundaries in compose.yaml.
type Config struct {
	ListenHost   string
	ListenPort   int
	AllowedHosts []string
	Lookup       func(host string) ([]net.IP, error)
	Dial         func(network, address string) (net.Conn, error)
}

// Target is one allowlisted hostname pinned to a public IP.
type Target struct {
	Hostname string
	IP       net.IP
}

// FromEnv reads PROVISIONING_PROXY_* / ALLOWED_HOSTS the same way
// deploy/provisioning-proxy.mjs does.
func FromEnv() (Config, error) {
	cfg := Config{
		ListenHost: getenv("PROVISIONING_PROXY_HOST", "0.0.0.0"),
		ListenPort: 3128,
	}
	if raw := os.Getenv("PROVISIONING_PROXY_PORT"); raw != "" {
		port, err := parsePort(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid provisioning proxy port")
		}
		cfg.ListenPort = port
	}
	cfg.AllowedHosts = parseHosts(getenv("ALLOWED_HOSTS", defaultAllowedHosts))
	if err := cfg.Valid(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Valid rejects empty listen config.
func (c Config) Valid() error {
	if strings.TrimSpace(c.ListenHost) == "" {
		return fmt.Errorf("provisioning proxy host is required")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("invalid provisioning proxy port")
	}
	if len(c.AllowedHosts) == 0 {
		return fmt.Errorf("ALLOWED_HOSTS must contain at least one hostname")
	}
	return nil
}

func (c Config) listenAddr() string {
	return net.JoinHostPort(c.ListenHost, fmt.Sprintf("%d", c.ListenPort))
}

func (c Config) lookup(host string) ([]net.IP, error) {
	if c.Lookup != nil {
		return c.Lookup(host)
	}
	return net.LookupIP(host)
}

func (c Config) dial(network, address string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(network, address)
	}
	return net.Dial(network, address)
}

func parseHosts(raw string) []string {
	out := make([]string, 0)
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		host := strings.ToLower(strings.TrimSpace(part))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, domain := range allowed {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// ResolveAndValidateHost allowlists the hostname then fail-closes if any
// resolved address is private, loopback, link-local, or metadata.
func (c Config) ResolveAndValidateHost(hostname string) (*Target, error) {
	host := strings.ToLower(strings.TrimSpace(hostname))
	if host == "" || !hostAllowed(host, c.AllowedHosts) {
		return nil, fmt.Errorf("destination host is not allowlisted")
	}
	addrs, err := c.lookup(host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("destination host could not be resolved")
	}
	for _, addr := range addrs {
		if ForbiddenIP(addr) {
			return nil, fmt.Errorf("destination resolves to a forbidden IP address")
		}
	}
	return &Target{Hostname: host, IP: addrs[0]}, nil
}

// ForbiddenIP reports whether ip is private, loopback, link-local, metadata,
// documentation, multicast, or otherwise unsafe for helper egress.
func ForbiddenIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		return forbiddenIPv4(v4)
	}
	return forbiddenIPv6(ip)
}

func forbiddenIPv4(v4 net.IP) bool {
	if v4 == nil || len(v4) < 4 {
		return true
	}
	b0, b1, b2 := v4[0], v4[1], v4[2]
	switch {
	case b0 == 0:
		return true
	case b0 == 10:
		return true
	case b0 == 100 && b1 >= 64 && b1 <= 127:
		return true
	case b0 == 127:
		return true
	case b0 == 169 && b1 == 254:
		return true
	case b0 == 172 && b1 >= 16 && b1 <= 31:
		return true
	case b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2):
		return true
	case b0 == 192 && b1 == 168:
		return true
	case b0 == 198 && (b1 == 18 || b1 == 19 || (b1 == 51 && b2 == 100)):
		return true
	case b0 == 203 && b1 == 0 && b2 == 113:
		return true
	case b0 >= 224:
		return true
	default:
		return false
	}
}

func forbiddenIPv6(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if len(ip) == net.IPv6len {
		if ip[0]&0xfe == 0xfc { // fc00::/7
			return true
		}
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 { // 2001:db8::/32
			return true
		}
	}
	return false
}

func parsePort(raw string) (int, error) {
	n := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid port")
		}
		n = n*10 + int(r-'0')
		if n > 65535 {
			return 0, fmt.Errorf("invalid port")
		}
	}
	if n < 1 {
		return 0, fmt.Errorf("invalid port")
	}
	return n, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
