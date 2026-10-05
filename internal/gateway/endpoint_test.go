package gateway

import (
	"net"
	"strings"
	"testing"
)

func publicExample(host string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

func TestValidateEndpointRejectsSSRFShapes(t *testing.T) {
	opts := EndpointOptions{Resolve: publicExample}
	cases := []string{
		"https://user:token@example.com/mcp",
		"https://example.com/mcp?token=1",
		"https://example.com/mcp#frag",
		"http://example.com/mcp",
		"https://127.0.0.1/mcp",
		"https://10.0.0.1/mcp",
		"https://169.254.169.254/mcp",
		"https://localhost/mcp",
		"file:///etc/passwd",
		"https://internal/mcp",
	}
	for _, raw := range cases {
		if _, err := ValidateEndpoint(raw, opts); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	got, err := ValidateEndpoint("https://example.com/mcp", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 1 || got.Addresses[0].String() != "93.184.216.34" {
		t.Fatalf("pin %v", got.Addresses)
	}
}

func TestValidateEndpointErrorsDoNotEchoURL(t *testing.T) {
	_, err := ValidateEndpoint("https://user:super-secret-token@127.0.0.1/mcp", EndpointOptions{})
	if err == nil {
		t.Fatal("expected fail")
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("error echoed credential: %v", err)
	}
}

func TestPrivateOptInStillBlocksLinkLocal(t *testing.T) {
	_, err := ValidateEndpoint("https://169.254.169.254/mcp", EndpointOptions{AllowPrivateEndpoints: true})
	if err == nil {
		t.Fatal("metadata address must stay blocked")
	}
}

func TestConfiguredEndpointExactPath(t *testing.T) {
	got, err := ValidateEndpoint("https://example.com/mcp", EndpointOptions{Resolve: publicExample})
	if err != nil {
		t.Fatal(err)
	}
	if !IsConfiguredEndpoint("https://example.com/mcp", got.URL) {
		t.Fatal("same path")
	}
	if IsConfiguredEndpoint("https://example.com/other", got.URL) {
		t.Fatal("other path must not carry credentials")
	}
}

func TestValidateEndpointPinsResolvedAddressesAndRejectsPrivateDNS(t *testing.T) {
	_, err := ValidateEndpoint("https://example.com/mcp", EndpointOptions{
		Resolve: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil },
	})
	if err == nil {
		t.Fatal("rebinding to loopback must fail")
	}
	if strings.Contains(err.Error(), "example.com") {
		t.Fatalf("error echoed host: %v", err)
	}
	got, err := ValidateEndpoint("https://github.com/mcp", EndpointOptions{
		Resolve: func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 2 {
		t.Fatalf("%v", got.Addresses)
	}
}
