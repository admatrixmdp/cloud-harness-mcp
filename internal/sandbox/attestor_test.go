package sandbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func testAttestor() FirewallAttestor {
	return FirewallAttestor{
		NetworkName:     DefaultDependencyNet,
		BridgeInterface: DefaultBridgeInterface,
		BridgeSubnet:    DefaultBridgeSubnet,
		DNSResolvers:    []string{"8.8.8.8", "1.1.1.1"},
	}
}

func validNetworkInspect() map[string]any {
	return map[string]any{
		"Name":       DefaultDependencyNet,
		"Driver":     "bridge",
		"EnableIPv6": false,
		"Options": map[string]any{
			"com.docker.network.bridge.name":                 DefaultBridgeInterface,
			"com.docker.network.bridge.enable_icc":           "false",
			"com.docker.network.bridge.enable_ip_masquerade": "false",
		},
		"IPAM": map[string]any{
			"Config": []any{map[string]any{"Subnet": DefaultBridgeSubnet}},
		},
	}
}

const validIptables = `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
:CHM-INPUT-v1 - [0:0]
:CHM-EGRESS-v1 - [0:0]
-A FORWARD -j DOCKER-USER
-A INPUT -i chm-egress0 -j CHM-INPUT-v1
-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1
-A CHM-INPUT-v1 -j REJECT --reject-with icmp-port-unreachable
-A CHM-EGRESS-v1 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A CHM-EGRESS-v1 -d 169.254.0.0/16 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 10.0.0.0/8 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 172.16.0.0/12 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 192.168.0.0/16 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 127.0.0.0/8 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 100.64.0.0/10 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 0.0.0.0/8 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 224.0.0.0/4 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 240.0.0.0/4 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 8.8.8.8/32 -p udp -m udp --dport 53 -j ACCEPT
-A CHM-EGRESS-v1 -d 8.8.8.8/32 -p tcp -m tcp --dport 53 -j ACCEPT
-A CHM-EGRESS-v1 -d 1.1.1.1/32 -p udp -m udp --dport 53 -j ACCEPT
-A CHM-EGRESS-v1 -d 1.1.1.1/32 -p tcp -m tcp --dport 53 -j ACCEPT
-A CHM-EGRESS-v1 -p tcp -m tcp --dport 80 -j ACCEPT
-A CHM-EGRESS-v1 -p tcp -m tcp --dport 443 -j ACCEPT
-A CHM-EGRESS-v1 -j REJECT --reject-with icmp-port-unreachable
COMMIT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 172.30.240.0/24 -p tcp -m multiport --dports 80,443 -j MASQUERADE
-A POSTROUTING -s 172.30.240.0/24 -p udp -d 8.8.8.8/32 --dport 53 -j MASQUERADE
-A POSTROUTING -s 172.30.240.0/24 -p tcp -d 8.8.8.8/32 --dport 53 -j MASQUERADE
-A POSTROUTING -s 172.30.240.0/24 -p udp -d 1.1.1.1/32 --dport 53 -j MASQUERADE
-A POSTROUTING -s 172.30.240.0/24 -p tcp -d 1.1.1.1/32 --dport 53 -j MASQUERADE
COMMIT
`

const validNatChain = `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
:CHM-INPUT-v1 - [0:0]
:CHM-EGRESS-v1 - [0:0]
-A FORWARD -j DOCKER-USER
-A INPUT -i chm-egress0 -j CHM-INPUT-v1
-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1
-A CHM-INPUT-v1 -j REJECT --reject-with icmp-port-unreachable
-A CHM-EGRESS-v1 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A CHM-EGRESS-v1 -d 169.254.0.0/16 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 10.0.0.0/8 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 172.16.0.0/12 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 192.168.0.0/16 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 127.0.0.0/8 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 100.64.0.0/10 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 0.0.0.0/8 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 224.0.0.0/4 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 240.0.0.0/4 -j REJECT --reject-with icmp-admin-prohibited
-A CHM-EGRESS-v1 -d 8.8.8.8/32 -p udp -m udp --dport 53 -j ACCEPT
-A CHM-EGRESS-v1 -d 8.8.8.8/32 -p tcp -m tcp --dport 53 -j ACCEPT
-A CHM-EGRESS-v1 -d 1.1.1.1/32 -p udp -m udp --dport 53 -j ACCEPT
-A CHM-EGRESS-v1 -d 1.1.1.1/32 -p tcp -m tcp --dport 53 -j ACCEPT
-A CHM-EGRESS-v1 -p tcp -m tcp --dport 80 -j ACCEPT
-A CHM-EGRESS-v1 -p tcp -m tcp --dport 443 -j ACCEPT
-A CHM-EGRESS-v1 -j REJECT --reject-with icmp-port-unreachable
COMMIT
*nat
:POSTROUTING ACCEPT [0:0]
:CHM-NAT-v1 - [0:0]
-A POSTROUTING -s 172.30.240.0/24 -j CHM-NAT-v1
-A CHM-NAT-v1 -p tcp -m multiport --dports 80,443 -j MASQUERADE
-A CHM-NAT-v1 -p udp -d 8.8.8.8/32 --dport 53 -j MASQUERADE
-A CHM-NAT-v1 -p tcp -d 8.8.8.8/32 --dport 53 -j MASQUERADE
-A CHM-NAT-v1 -p udp -d 1.1.1.1/32 --dport 53 -j MASQUERADE
-A CHM-NAT-v1 -p tcp -d 1.1.1.1/32 --dport 53 -j MASQUERADE
COMMIT
`

func TestVerifyDockerNetworkAcceptsCanonicalBridge(t *testing.T) {
	got := testAttestor().VerifyDockerNetwork(validNetworkInspect())
	if !got.OK {
		t.Fatalf("%+v", got)
	}
}

func TestVerifyDockerNetworkFailClosed(t *testing.T) {
	a := testAttestor()
	if got := a.VerifyDockerNetwork(nil); got.OK || !strings.Contains(got.Reason, "is not found") {
		t.Fatalf("nil: %+v", got)
	}
	overlay := validNetworkInspect()
	overlay["Driver"] = "overlay"
	if got := a.VerifyDockerNetwork(overlay); got.OK || !strings.Contains(got.Reason, "bridge") {
		t.Fatalf("overlay: %+v", got)
	}
	icc := validNetworkInspect()
	icc["Options"].(map[string]any)["com.docker.network.bridge.enable_icc"] = "true"
	if got := a.VerifyDockerNetwork(icc); got.OK || !strings.Contains(got.Reason, "enable_icc") {
		t.Fatalf("icc: %+v", got)
	}
	ipv6 := validNetworkInspect()
	ipv6["EnableIPv6"] = true
	if got := a.VerifyDockerNetwork(ipv6); got.OK || !strings.Contains(got.Reason, "IPv6") {
		t.Fatalf("ipv6: %+v", got)
	}
	wrongIf := validNetworkInspect()
	wrongIf["Options"].(map[string]any)["com.docker.network.bridge.name"] = "wrong-if"
	if got := a.VerifyDockerNetwork(wrongIf); got.OK || !strings.Contains(got.Reason, "chm-egress0") {
		t.Fatalf("iface: %+v", got)
	}
	missingName := validNetworkInspect()
	delete(missingName["Options"].(map[string]any), "com.docker.network.bridge.name")
	if got := a.VerifyDockerNetwork(missingName); got.OK || !strings.Contains(got.Reason, "bridge interface must be exactly 'chm-egress0'") {
		t.Fatalf("missing name: %+v", got)
	}
	missingSubnet := validNetworkInspect()
	missingSubnet["IPAM"] = map[string]any{"Config": []any{}}
	if got := a.VerifyDockerNetwork(missingSubnet); got.OK || !strings.Contains(got.Reason, "exactly one subnet") {
		t.Fatalf("subnet: %+v", got)
	}
	missingMasq := validNetworkInspect()
	delete(missingMasq["Options"].(map[string]any), "com.docker.network.bridge.enable_ip_masquerade")
	if got := a.VerifyDockerNetwork(missingMasq); got.OK || !strings.Contains(got.Reason, "enable_ip_masquerade") {
		t.Fatalf("masq: %+v", got)
	}
}

func TestParseFirewallRulesAcceptsCanonicalAndNatChain(t *testing.T) {
	a := testAttestor()
	if got := a.ParseFirewallRules(validIptables); !got.OK {
		t.Fatalf("canonical: %+v", got)
	}
	if got := a.ParseFirewallRules(validNatChain); !got.OK {
		t.Fatalf("nat chain: %+v", got)
	}
}

func TestParseFirewallRulesFailClosed(t *testing.T) {
	a := testAttestor()
	if got := a.ParseFirewallRules(""); got.OK || got.Reason != "empty firewall configuration" {
		t.Fatalf("empty: %+v", got)
	}
	if got := a.ParseFirewallRules(strings.ReplaceAll(validIptables, "-A CHM-EGRESS-v1 -d 169.254.0.0/16 -j REJECT --reject-with icmp-admin-prohibited\n", "")); got.OK {
		t.Fatal("missing metadata")
	}
	if got := a.ParseFirewallRules(strings.ReplaceAll(validIptables, "-A CHM-EGRESS-v1 -p tcp -m tcp --dport 443 -j ACCEPT\n", "")); got.OK {
		t.Fatal("missing 443")
	}
	if got := a.ParseFirewallRules(strings.ReplaceAll(validIptables, "-A INPUT -i chm-egress0 -j CHM-INPUT-v1\n", "")); got.OK {
		t.Fatal("missing input jump")
	}
	if got := a.ParseFirewallRules(strings.ReplaceAll(validIptables, "-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1\n", "")); got.OK {
		t.Fatal("missing docker-user jump")
	}

	reordered := strings.Replace(validIptables,
		"-A CHM-EGRESS-v1 -m conntrack --ctstate ESTABLISHED -j ACCEPT\n-A CHM-EGRESS-v1 -d 169.254.0.0/16",
		"-A CHM-EGRESS-v1 -m conntrack --ctstate ESTABLISHED -j ACCEPT\n-A CHM-EGRESS-v1 -p tcp --dport 80 -j ACCEPT\n-A CHM-EGRESS-v1 -d 169.254.0.0/16",
		1)
	if got := a.ParseFirewallRules(reordered); got.OK || !strings.Contains(got.Reason, "port 80/443 allow rules must not precede forbidden destination deny rules") {
		t.Fatalf("reorder: %+v", got)
	}

	directAccept := strings.Replace(validIptables, "-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1", "-A DOCKER-USER -i chm-egress0 -j ACCEPT", 1)
	if got := a.ParseFirewallRules(directAccept); got.OK || !strings.Contains(got.Reason, "invalid or broad target jump for 'chm-egress0' in DOCKER-USER") {
		t.Fatalf("direct accept: %+v", got)
	}

	preceding := strings.Replace(validIptables, "-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1", "-A DOCKER-USER -j ACCEPT\n-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1", 1)
	if got := a.ParseFirewallRules(preceding); got.OK || !strings.Contains(got.Reason, "must be the first DOCKER-USER rule") {
		t.Fatalf("preceding: %+v", got)
	}

	broadNAT := strings.Replace(validIptables,
		"-A POSTROUTING -s 172.30.240.0/24 -p tcp -m multiport --dports 80,443 -j MASQUERADE",
		"-A POSTROUTING -s 172.30.240.0/24 -j MASQUERADE",
		1)
	if got := a.ParseFirewallRules(broadNAT); got.OK || !strings.Contains(got.Reason, "unauthorized or widened MASQUERADE rule") {
		t.Fatalf("broad nat: %+v", got)
	}

	broadAccept := strings.Replace(validIptables, "-A CHM-EGRESS-v1 -j REJECT --reject-with icmp-port-unreachable", "-A CHM-EGRESS-v1 -j ACCEPT\n-A CHM-EGRESS-v1 -j REJECT --reject-with icmp-port-unreachable", 1)
	if got := a.ParseFirewallRules(broadAccept); got.OK || !strings.Contains(got.Reason, "unauthorized or widened rule") {
		t.Fatalf("broad accept: %+v", got)
	}

	widened := strings.Replace(validIptables, "-A CHM-EGRESS-v1 -p tcp -m tcp --dport 80 -j ACCEPT", "-A CHM-EGRESS-v1 -p tcp --dport 8000 -j ACCEPT\n-A CHM-EGRESS-v1 -p tcp -m tcp --dport 80 -j ACCEPT", 1)
	if got := a.ParseFirewallRules(widened); got.OK || !strings.Contains(got.Reason, "unauthorized or widened rule") {
		t.Fatalf("port 8000: %+v", got)
	}
}

func TestFirewallAttestorVerifyUsesInspectThenGuard(t *testing.T) {
	inspectJSON, err := jsonMarshal(validNetworkInspect())
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	a := testAttestor()
	a.GuardImage = "cloud-harness-network-guard:local"
	a.Run = func(_ context.Context, args []string, _ string) (Result, error) {
		joined := strings.Join(args, " ")
		calls = append(calls, joined)
		if args[0] == "network" {
			return Result{Stdout: inspectJSON, ExitCode: 0}, nil
		}
		if args[0] == "run" {
			if strings.Contains(joined, "docker.sock") {
				t.Fatal("socket leaked into guard probe")
			}
			if !strings.Contains(joined, "--cap-drop ALL") || !strings.Contains(joined, "--cap-add NET_ADMIN") {
				t.Fatalf("caps: %s", joined)
			}
			if !strings.Contains(joined, "--user 0:0") || !strings.Contains(joined, "cloud-harness-network-guard:local") {
				t.Fatalf("image/user: %s", joined)
			}
			return Result{Stdout: validIptables, ExitCode: 0}, nil
		}
		t.Fatalf("unexpected docker args %v", args)
		return Result{}, nil
	}
	ok, reason, err := a.Verify(context.Background())
	if err != nil || !ok {
		t.Fatalf("ok=%v reason=%q err=%v", ok, reason, err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls=%v", calls)
	}

	a.Run = func(_ context.Context, args []string, _ string) (Result, error) {
		if args[0] == "network" {
			return Result{ExitCode: 1, Stderr: "not found"}, nil
		}
		t.Fatal("guard must not run when inspect fails")
		return Result{}, nil
	}
	ok, reason, err = a.Verify(context.Background())
	if err != nil || ok || !strings.Contains(reason, "is not found") {
		t.Fatalf("missing net: ok=%v reason=%q err=%v", ok, reason, err)
	}
}

func jsonMarshal(v map[string]any) (string, error) {
	raw, err := json.Marshal(v)
	return string(raw), err
}
