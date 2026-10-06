package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	DefaultBridgeInterface = "chm-egress0"
	DefaultBridgeSubnet    = "172.30.240.0/24"
	DefaultGuardImage      = "cloud-harness-network-guard:local"
)

var defaultDNSResolvers = []string{"8.8.8.8", "1.1.1.1"}

var requiredDenyCIDRs = []string{
	"169.254.0.0/16",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"100.64.0.0/10",
	"0.0.0.0/8",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

var (
	reConntrack = regexp.MustCompile(`^-A\s+\S+\s+-m\s+conntrack\s+--ctstate\s+ESTABLISHED(?:,RELATED)?\s+-j\s+ACCEPT$`)
	reDeny      = regexp.MustCompile(`^-A\s+\S+\s+-d\s+\S+\s+-j\s+(?:REJECT|DROP)(?:\s+--reject-with\s+\S+)?$`)
	reWeb80     = regexp.MustCompile(`^-A\s+\S+\s+-p\s+tcp(?:\s+-m\s+tcp)?\s+--dport\s+80\s+-j\s+ACCEPT$`)
	reWeb443    = regexp.MustCompile(`^-A\s+\S+\s+-p\s+tcp(?:\s+-m\s+tcp)?\s+--dport\s+443\s+-j\s+ACCEPT$`)
	reWebMulti  = regexp.MustCompile(`^-A\s+\S+\s+-p\s+tcp\s+-m\s+multiport\s+--dports\s+80,443\s+-j\s+ACCEPT$`)
	reTerminal  = regexp.MustCompile(`^-A\s+\S+\s+-j\s+(?:REJECT|DROP)(?:\s+--reject-with\s+\S+)?$`)
	reJump      = regexp.MustCompile(`-j\s+([A-Za-z0-9_-]+)`)
	reChainName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	reDport80   = regexp.MustCompile(`--dport\s+80\b`)
	reDport443  = regexp.MustCompile(`--dport\s+443\b`)
	reTCP       = regexp.MustCompile(`-p\s+tcp\b`)
	reUDP       = regexp.MustCompile(`-p\s+udp\b`)
	reAccept    = regexp.MustCompile(`-j\s+ACCEPT\b`)
	reDport53   = regexp.MustCompile(`--dport\s+53\b`)
	reDest      = regexp.MustCompile(`-d\s+`)
)

// FirewallAttestor verifies the dedicated dependency-access bridge and the
// host iptables snapshot. Failure never silently downgrades the profile.
type FirewallAttestor struct {
	NetworkName     string
	BridgeInterface string
	BridgeSubnet    string
	DNSResolvers    []string
	GuardImage      string
	Run             Runner
}

func (a FirewallAttestor) networkName() string {
	if a.NetworkName != "" {
		return a.NetworkName
	}
	return DefaultDependencyNet
}

func (a FirewallAttestor) bridgeInterface() string {
	if a.BridgeInterface != "" {
		return a.BridgeInterface
	}
	return DefaultBridgeInterface
}

func (a FirewallAttestor) bridgeSubnet() string {
	if a.BridgeSubnet != "" {
		return a.BridgeSubnet
	}
	return DefaultBridgeSubnet
}

func (a FirewallAttestor) dns() []string {
	if len(a.DNSResolvers) > 0 {
		return a.DNSResolvers
	}
	return append([]string{}, defaultDNSResolvers...)
}

func (a FirewallAttestor) guardImage() string {
	if a.GuardImage != "" {
		return a.GuardImage
	}
	return DefaultGuardImage
}

func (a FirewallAttestor) runner() Runner {
	if a.Run != nil {
		return a.Run
	}
	return Engine{}.cli
}

// Verify implements Attestor: inspect the dedicated bridge, then parse the
// host iptables-save snapshot from the network-guard image. Fail closed.
func (a FirewallAttestor) Verify(ctx context.Context) (bool, string, error) {
	netJSON, err := a.inspectNetwork(ctx)
	if err != nil {
		return false, err.Error(), nil
	}
	if res := a.VerifyDockerNetwork(netJSON); !res.OK {
		return false, res.Reason, nil
	}
	fw, err := a.attestHostKernel(ctx)
	if err != nil {
		return false, err.Error(), nil
	}
	if !fw.OK {
		return false, fw.Reason, nil
	}
	return true, "", nil
}

type checkResult struct {
	OK     bool
	Reason string
}

func failCheck(reason string) checkResult { return checkResult{Reason: reason} }

func okCheck() checkResult { return checkResult{OK: true} }

func (a FirewallAttestor) inspectNetwork(ctx context.Context) (map[string]any, error) {
	res, err := a.runner()(ctx, []string{"network", "inspect", a.networkName(), "--format", "{{json .}}"}, "")
	if err != nil {
		return nil, fmt.Errorf("dedicated bridge network '%s' is not found", a.networkName())
	}
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) == "" {
		return nil, fmt.Errorf("dedicated bridge network '%s' is not found", a.networkName())
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &obj); err != nil {
		var arr []map[string]any
		if err2 := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &arr); err2 != nil || len(arr) == 0 {
			return nil, fmt.Errorf("dedicated bridge network '%s' is not found", a.networkName())
		}
		obj = arr[0]
	}
	return obj, nil
}

func (a FirewallAttestor) attestHostKernel(ctx context.Context) (checkResult, error) {
	res, err := a.runner()(ctx, []string{
		"run", "--rm", "--pull", "never", "--network", "host",
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
		"--security-opt", "no-new-privileges",
		"--user", "0:0",
		a.guardImage(),
	}, "")
	if err != nil {
		return failCheck(fmt.Sprintf("host firewall attestation error: %v", err)), nil
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		return failCheck(fmt.Sprintf("host firewall probe failed (exit code %d): %s", res.ExitCode, msg)), nil
	}
	return a.ParseFirewallRules(res.Stdout), nil
}

// VerifyDockerNetwork checks the dedicated bridge inspect object.
func (a FirewallAttestor) VerifyDockerNetwork(inspect map[string]any) checkResult {
	if inspect == nil {
		return failCheck(fmt.Sprintf("dedicated bridge network '%s' is not found", a.networkName()))
	}
	if str(inspect["Driver"]) != "bridge" {
		return failCheck(fmt.Sprintf("network driver must be 'bridge', found '%s'", str(inspect["Driver"])))
	}
	options := optionMap(inspect["Options"])
	bridge := str(options["com.docker.network.bridge.name"])
	if bridge != a.bridgeInterface() {
		found := bridge
		if found == "" {
			found = "(unset)"
		}
		return failCheck(fmt.Sprintf("bridge interface must be exactly '%s', found '%s'", a.bridgeInterface(), found))
	}
	if str(options["com.docker.network.bridge.enable_icc"]) != "false" {
		return failCheck("inter-container communication (enable_icc) must be 'false'")
	}
	if str(options["com.docker.network.bridge.enable_ip_masquerade"]) != "false" {
		return failCheck("default IP masquerade (enable_ip_masquerade) must be 'false'")
	}
	if inspect["EnableIPv6"] != false {
		return failCheck("IPv6 must be explicitly disabled for dependency-access network")
	}
	ipam, _ := inspect["IPAM"].(map[string]any)
	var subnets []string
	if ipam != nil {
		for _, rec := range ipamConfigs(ipam["Config"]) {
			if s := str(rec["Subnet"]); s != "" {
				subnets = append(subnets, s)
			}
		}
	}
	if len(subnets) != 1 || subnets[0] != a.bridgeSubnet() {
		found := strings.Join(subnets, ", ")
		if found == "" {
			found = "(none)"
		}
		return failCheck(fmt.Sprintf("network must have exactly one subnet '%s', found '%s'", a.bridgeSubnet(), found))
	}
	return okCheck()
}

// ParseFirewallRules attests an iptables-save snapshot. Empty input fails closed.
func (a FirewallAttestor) ParseFirewallRules(text string) checkResult {
	if strings.TrimSpace(text) == "" {
		return failCheck("empty firewall configuration")
	}
	var lines []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}

	forward := filterPrefix(lines, "-A FORWARD")
	if len(forward) == 0 {
		return failCheck("missing FORWARD jump rule to DOCKER-USER")
	}
	firstForward := collapseSpace(forward[0])
	if firstForward != "-A FORWARD -j DOCKER-USER" {
		return failCheck(fmt.Sprintf("first FORWARD rule must be exactly '-A FORWARD -j DOCKER-USER', found '%s'", firstForward))
	}

	iface := a.bridgeInterface()
	input := filterPrefix(lines, "-A INPUT")
	if len(input) == 0 {
		return failCheck(fmt.Sprintf("missing INPUT jump rule for interface '%s'", iface))
	}
	firstInput := collapseSpace(input[0])
	inputPrefix := "-A INPUT -i " + iface + " -j "
	if !strings.HasPrefix(firstInput, inputPrefix) {
		return failCheck(fmt.Sprintf("managed INPUT jump for '%s' must be the first INPUT rule, found '%s'", iface, firstInput))
	}
	inputTarget := strings.TrimSpace(strings.TrimPrefix(firstInput, inputPrefix))
	if inputTarget == "ACCEPT" || inputTarget == "RETURN" || !reChainName.MatchString(inputTarget) {
		return failCheck(fmt.Sprintf("invalid or broad target jump for '%s' in INPUT: %s", iface, inputTarget))
	}
	if inputTarget != "REJECT" && inputTarget != "DROP" {
		inputChain := filterPrefix(lines, "-A "+inputTarget)
		if len(inputChain) == 0 {
			return failCheck(fmt.Sprintf("INPUT target chain '%s' has no rules", inputTarget))
		}
		for _, rule := range inputChain {
			target := jumpTarget(rule)
			if target == "RETURN" {
				return failCheck(fmt.Sprintf("INPUT target chain '%s' must not contain RETURN rules: %s", inputTarget, rule))
			}
			if target != "REJECT" && target != "DROP" {
				return failCheck(fmt.Sprintf("INPUT target chain '%s' contains unauthorized target '%s': %s", inputTarget, target, rule))
			}
		}
		last := inputChain[len(inputChain)-1]
		if !strings.Contains(last, "-j REJECT") && !strings.Contains(last, "-j DROP") {
			return failCheck(fmt.Sprintf("chain '%s' must terminate with REJECT or DROP", inputTarget))
		}
	}

	dockerUser := filterPrefix(lines, "-A DOCKER-USER")
	if len(dockerUser) == 0 {
		return failCheck(fmt.Sprintf("missing DOCKER-USER jump rule for interface '%s'", iface))
	}
	firstEgress := collapseSpace(dockerUser[0])
	egressPrefix := "-A DOCKER-USER -i " + iface + " -j "
	if !strings.HasPrefix(firstEgress, egressPrefix) {
		return failCheck(fmt.Sprintf("managed DOCKER-USER jump for '%s' must be the first DOCKER-USER rule, found '%s'", iface, firstEgress))
	}
	egressTarget := strings.TrimSpace(strings.TrimPrefix(firstEgress, egressPrefix))
	if egressTarget == "ACCEPT" || egressTarget == "RETURN" || !reChainName.MatchString(egressTarget) {
		return failCheck(fmt.Sprintf("invalid or broad target jump for '%s' in DOCKER-USER: %s", iface, egressTarget))
	}

	egress := filterPrefix(lines, "-A "+egressTarget)
	if len(egress) == 0 {
		return failCheck(fmt.Sprintf("egress target chain '%s' has no rules", egressTarget))
	}
	firstRule := egress[0]
	if !strings.Contains(firstRule, "conntrack") || !strings.Contains(firstRule, "ESTABLISHED") || !strings.Contains(firstRule, "-j ACCEPT") {
		return failCheck("first rule in egress chain must be ESTABLISHED conntrack accept")
	}

	maxDeny := -1
	for _, cidr := range requiredDenyCIDRs {
		idx := indexFunc(egress, func(l string) bool {
			return strings.Contains(l, "-d "+cidr) && (strings.Contains(l, "-j REJECT") || strings.Contains(l, "-j DROP"))
		})
		if idx == -1 {
			return failCheck(fmt.Sprintf("egress chain missing deny rule for '%s'", cidr))
		}
		if idx > maxDeny {
			maxDeny = idx
		}
	}
	port80 := indexFunc(egress, func(l string) bool {
		return reDport80.MatchString(l) && reTCP.MatchString(l) && reAccept.MatchString(l) && !reDest.MatchString(l)
	})
	port443 := indexFunc(egress, func(l string) bool {
		return reDport443.MatchString(l) && reTCP.MatchString(l) && reAccept.MatchString(l) && !reDest.MatchString(l)
	})
	if port80 == -1 || port443 == -1 {
		return failCheck("egress chain missing HTTP/HTTPS (ports 80, 443) accept rules")
	}
	if maxDeny > port80 || maxDeny > port443 {
		return failCheck("port 80/443 allow rules must not precede forbidden destination deny rules")
	}

	for _, resolver := range a.dns() {
		hasUDP := anyLine(egress, func(l string) bool {
			return strings.Contains(l, "-d "+resolver) && reDport53.MatchString(l) && reUDP.MatchString(l) && reAccept.MatchString(l)
		})
		hasTCP := anyLine(egress, func(l string) bool {
			return strings.Contains(l, "-d "+resolver) && reDport53.MatchString(l) && reTCP.MatchString(l) && reAccept.MatchString(l)
		})
		if !hasUDP {
			return failCheck(fmt.Sprintf("egress chain missing DNS UDP accept rule for '%s'", resolver))
		}
		if !hasTCP {
			return failCheck(fmt.Sprintf("egress chain missing DNS TCP accept rule for '%s'", resolver))
		}
	}

	for _, rule := range egress {
		if !authorizedEgress(rule, a.dns()) {
			return failCheck("egress chain contains unauthorized or widened rule: " + rule)
		}
	}
	last := egress[len(egress)-1]
	if !strings.Contains(last, "-j REJECT") && !strings.Contains(last, "-j DROP") {
		return failCheck("egress chain must end with terminal REJECT or DROP")
	}

	natIndex := indexOf(lines, "*nat")
	if natIndex == -1 {
		return failCheck("nat table section missing; scoped MASQUERADE rules are required")
	}
	natLines := lines[natIndex:]
	postrouting := filterPrefix(natLines, "-A POSTROUTING")
	subnet := a.bridgeSubnet()
	var subnetJumps []string
	for _, l := range postrouting {
		if strings.Contains(l, "-s "+subnet) {
			subnetJumps = append(subnetJumps, l)
		}
	}
	if len(subnetJumps) == 0 {
		return failCheck(fmt.Sprintf("no scoped MASQUERADE or NAT jump rules found for '%s' in nat table", subnet))
	}
	firstJump := subnetJumps[0]
	firstJumpIdx := indexOf(postrouting, firstJump)
	for _, prior := range postrouting[:max(0, firstJumpIdx)] {
		if (strings.Contains(prior, "-j MASQUERADE") || strings.Contains(prior, "-j ACCEPT")) &&
			(!strings.Contains(prior, "-s ") || strings.Contains(prior, "-s "+subnet)) {
			return failCheck(fmt.Sprintf("broad MASQUERADE or ACCEPT rule precedes POSTROUTING jump for '%s'", subnet))
		}
	}
	natTarget := jumpTarget(firstJump)
	if natTarget == "" || natTarget == "ACCEPT" || natTarget == "RETURN" {
		return failCheck(fmt.Sprintf("invalid or broad target jump for subnet '%s' in POSTROUTING", subnet))
	}
	var targetRules []string
	if natTarget == "MASQUERADE" {
		targetRules = subnetJumps
	} else {
		targetRules = filterPrefix(natLines, "-A "+natTarget)
		if len(targetRules) == 0 {
			return failCheck(fmt.Sprintf("nat target chain '%s' has no rules", natTarget))
		}
	}
	for _, rule := range targetRules {
		if strings.Contains(rule, "-j MASQUERADE") {
			isWeb := strings.Contains(rule, "-p tcp") &&
				(strings.Contains(rule, "--dports 80,443") || strings.Contains(rule, "--dport 80") || strings.Contains(rule, "--dport 443")) &&
				!strings.Contains(rule, "-d ")
			isDNS := false
			for _, resolver := range a.dns() {
				if strings.Contains(rule, "-d "+resolver) && (strings.Contains(rule, "-p udp") || strings.Contains(rule, "-p tcp")) && strings.Contains(rule, "--dport 53") {
					isDNS = true
					break
				}
			}
			if !isWeb && !isDNS {
				return failCheck("nat target contains unauthorized or widened MASQUERADE rule: " + rule)
			}
		} else if strings.Contains(rule, "-j ACCEPT") {
			return failCheck("nat target must not contain broad ACCEPT rules: " + rule)
		}
	}
	hasWeb := false
	for _, l := range targetRules {
		if strings.Contains(l, "-j MASQUERADE") && (strings.Contains(l, "80") || strings.Contains(l, "443")) {
			hasWeb = true
			break
		}
	}
	if !hasWeb {
		return failCheck(fmt.Sprintf("missing scoped HTTP/HTTPS MASQUERADE rule for '%s'", subnet))
	}
	for _, resolver := range a.dns() {
		hasUDP := anyLine(targetRules, func(l string) bool {
			return strings.Contains(l, "-j MASQUERADE") && strings.Contains(l, "-d "+resolver) && strings.Contains(l, "-p udp") && strings.Contains(l, "--dport 53")
		})
		hasTCP := anyLine(targetRules, func(l string) bool {
			return strings.Contains(l, "-j MASQUERADE") && strings.Contains(l, "-d "+resolver) && strings.Contains(l, "-p tcp") && strings.Contains(l, "--dport 53")
		})
		if !hasUDP || !hasTCP {
			return failCheck(fmt.Sprintf("missing scoped UDP/TCP DNS MASQUERADE rule for resolver '%s'", resolver))
		}
	}
	return okCheck()
}

func authorizedEgress(rule string, resolvers []string) bool {
	if reConntrack.MatchString(rule) || reDeny.MatchString(rule) || reWeb80.MatchString(rule) || reWeb443.MatchString(rule) || reWebMulti.MatchString(rule) || reTerminal.MatchString(rule) {
		return true
	}
	for _, r := range resolvers {
		escaped := regexp.QuoteMeta(r)
		re1 := regexp.MustCompile(`^-A\s+\S+\s+-d\s+` + escaped + `(?:/32)?\s+-p\s+(?:udp|tcp)(?:\s+-m\s+(?:udp|tcp))?\s+--dport\s+53\s+-j\s+ACCEPT$`)
		re2 := regexp.MustCompile(`^-A\s+\S+\s+-p\s+(?:udp|tcp)(?:\s+-m\s+(?:udp|tcp))?\s+-d\s+` + escaped + `(?:/32)?\s+--dport\s+53\s+-j\s+ACCEPT$`)
		if re1.MatchString(rule) || re2.MatchString(rule) {
			return true
		}
	}
	return false
}

func filterPrefix(lines []string, prefix string) []string {
	out := make([]string, 0)
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func jumpTarget(rule string) string {
	m := reJump.FindStringSubmatch(rule)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func indexFunc(lines []string, fn func(string) bool) int {
	for i, l := range lines {
		if fn(l) {
			return i
		}
	}
	return -1
}

func anyLine(lines []string, fn func(string) bool) bool {
	return indexFunc(lines, fn) >= 0
}

func indexOf(lines []string, want string) int {
	for i, l := range lines {
		if l == want {
			return i
		}
	}
	return -1
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func optionMap(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case map[string]string:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = val
		}
		return out
	default:
		return map[string]any{}
	}
}

func ipamConfigs(v any) []map[string]any {
	switch t := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, item := range t {
			if rec, ok := item.(map[string]any); ok {
				out = append(out, rec)
			}
		}
		return out
	case []map[string]any:
		return t
	default:
		return nil
	}
}
