package provisioning

import (
	"net"
	"testing"
)

func TestForbiddenIPMatchesTypeScript(t *testing.T) {
	forbid := []string{
		"127.0.0.1", "127.0.1.1", "0.0.0.0", "0.1.2.3",
		"169.254.169.254", "169.254.1.1",
		"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.100.50",
		"100.64.0.1", "100.127.255.255",
		"192.0.2.1", "198.51.100.1", "203.0.113.1",
		"224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:192.168.1.1",
		"::1", "::", "fe80::1", "fc00::1", "fd00::1234", "ff02::1", "2001:db8::1",
	}
	for _, raw := range forbid {
		if !ForbiddenIP(net.ParseIP(raw)) {
			t.Fatalf("%s must be forbidden", raw)
		}
	}
	allow := []string{"140.82.121.4", "1.1.1.1", "8.8.8.8"}
	for _, raw := range allow {
		if ForbiddenIP(net.ParseIP(raw)) {
			t.Fatalf("%s must be public", raw)
		}
	}
}

func TestResolveAndValidateHostAllowlistAndPin(t *testing.T) {
	cfg := Config{
		ListenHost:   "127.0.0.1",
		ListenPort:   3128,
		AllowedHosts: []string{"github.com"},
		Lookup: func(host string) ([]net.IP, error) {
			if host == "github.com" {
				return []net.IP{net.ParseIP("140.82.121.4")}, nil
			}
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	}
	got, err := cfg.ResolveAndValidateHost("github.com")
	if err != nil || got.IP.String() != "140.82.121.4" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := cfg.ResolveAndValidateHost("evil-attacker.com"); err == nil {
		t.Fatal("non-allowlisted host")
	}
	if _, err := cfg.ResolveAndValidateHost("localhost"); err == nil {
		t.Fatal("localhost")
	}
	cfg.AllowedHosts = []string{"internal.example"}
	cfg.Lookup = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.1")}, nil }
	if _, err := cfg.ResolveAndValidateHost("internal.example"); err == nil {
		t.Fatal("private resolution must fail closed")
	}
	if _, err := cfg.ResolveAndValidateHost("api.github.com"); err == nil {
		t.Fatal("suffix without parent allow")
	}
	cfg.AllowedHosts = []string{"github.com"}
	cfg.Lookup = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("140.82.121.4")}, nil }
	if _, err := cfg.ResolveAndValidateHost("api.github.com"); err != nil {
		t.Fatalf("suffix of allowlisted domain: %v", err)
	}
}
