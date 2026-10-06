package api

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const maxEndpointURLLength = 2048

var unsafeHostSuffixes = []string{
	".localhost", ".local", ".internal", ".home", ".lan", ".corp", ".test", ".invalid", ".example", ".arpa",
}

func rejectUnsafeEndpoint(w http.ResponseWriter, body map[string]any, opts Options) bool {
	raw, ok := body["endpoint"].(string)
	if !ok {
		return false
	}
	if err := validateGatewayEndpoint(raw, opts); err != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_input", "message": err})
		return true
	}
	return false
}

func rejectAuthenticatedSSE(w http.ResponseWriter, body map[string]any) bool {
	transport, _ := body["transport"].(string)
	if transport != "sse" {
		return false
	}
	headers, _ := body["headers"].([]any)
	for _, raw := range headers {
		header, _ := raw.(map[string]any)
		if header == nil {
			continue
		}
		value := header["value"]
		if obj, ok := value.(map[string]any); ok {
			if ref, _ := obj["secretRef"].(string); strings.TrimSpace(ref) != "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error":   "invalid_input",
					"message": "authenticated SSE is not supported: credentials are attached only to the configured endpoint, so use transport streamable-http for a server that needs a secret header",
				})
				return true
			}
		}
	}
	return false
}

func validateGatewayEndpoint(rawURL string, opts Options) string {
	if rawURL == "" || len(rawURL) > maxEndpointURLLength {
		return "endpoint URL must be a non-empty string of at most 2048 characters"
	}
	if strings.Contains(rawURL, `\`) || strings.Contains(strings.ToLower(rawURL), "%2e") || strings.Contains(strings.ToLower(rawURL), "%2f") || strings.Contains(strings.ToLower(rawURL), "%5c") {
		return "endpoint URL must not contain backslashes or encoded path separators"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !parsed.IsAbs() {
		return "endpoint is not a valid absolute URL"
	}
	if parsed.User != nil {
		return "endpoint URL must not embed credentials"
	}
	if parsed.RawQuery != "" {
		return "endpoint URL must not contain a query string"
	}
	if parsed.Fragment != "" {
		return "endpoint URL must not contain a fragment"
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "endpoint URL must use https"
	}
	if parsed.Scheme == "http" && !opts.MCPGatewayAllowInsecureHTTP {
		return "cleartext http endpoints are refused unless the insecure http opt-in is enabled"
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" {
		return "endpoint hostname is not a public DNS name"
	}
	if ip := net.ParseIP(host); ip != nil {
		if !opts.MCPGatewayAllowPrivateEndpoints && unsafeAddress(ip) {
			return "endpoint resolves to a private, loopback, link-local, or metadata address"
		}
		if alwaysBlockedAddress(ip) {
			return "endpoint resolves to a link-local or metadata address, which is always refused"
		}
		return ""
	}
	if unsafeHostname(host) {
		return "endpoint hostname is not a public DNS name"
	}
	resolve := opts.MCPGatewayResolve
	if resolve == nil {
		resolve = net.LookupIP
	}
	addrs, err := resolve(host)
	if err != nil {
		return "endpoint hostname could not be resolved"
	}
	if len(addrs) == 0 {
		return "endpoint hostname did not resolve to an address"
	}
	for _, addr := range addrs {
		if !opts.MCPGatewayAllowPrivateEndpoints && unsafeAddress(addr) {
			return "endpoint resolves to a private, loopback, link-local, or metadata address"
		}
		if alwaysBlockedAddress(addr) {
			return "endpoint resolves to a link-local or metadata address, which is always refused"
		}
	}
	return ""
}

func unsafeHostname(host string) bool {
	if host == "localhost" || host == "metadata.google.internal" {
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
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	v4 := ip.To4()
	if v4 != nil {
		first, second, third := v4[0], v4[1], v4[2]
		if first == 0 || first == 100 && second >= 64 && second <= 127 ||
			first == 192 && second == 0 && (third == 0 || third == 2) ||
			first == 198 && (second == 18 || second == 19 || second == 51 && third == 100) ||
			first == 203 && second == 0 && third == 113 ||
			first >= 224 {
			return true
		}
		return false
	}
	// IPv6 documentation / ULA / multicast already partly covered; fail closed on unique-local.
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

func alwaysBlockedAddress(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func decodeMutation(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	body, err := decodeObject(r)
	if err != nil {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return nil, false
	}
	return body, true
}

func queryCSV(r *http.Request, name string) []string {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func knowledgeListQuery(r *http.Request) map[string]any {
	input := pageQuery(r)
	if kind := r.URL.Query().Get("kind"); kind != "" {
		input["kind"] = kind
	}
	if scope := r.URL.Query().Get("scope"); scope != "" {
		input["scope"] = scope
	}
	if projectID := r.URL.Query().Get("projectId"); projectID != "" {
		input["projectId"] = projectID
	}
	if journalType := r.URL.Query().Get("journalType"); journalType != "" {
		input["journalType"] = journalType
	}
	if tags := queryCSV(r, "tags"); len(tags) > 0 {
		input["tags"] = tags
	}
	if tagMatch := r.URL.Query().Get("tagMatch"); tagMatch != "" {
		input["tagMatch"] = tagMatch
	}
	return input
}

func knowledgeGraphQuery(r *http.Request) map[string]any {
	input := map[string]any{}
	if rootID := r.URL.Query().Get("rootId"); rootID != "" {
		input["rootId"] = rootID
	}
	if depth := queryInt(r, "depth"); depth > 0 {
		input["depth"] = depth
	}
	if maxNodes := queryInt(r, "maxNodes"); maxNodes > 0 {
		input["maxNodes"] = maxNodes
	}
	if kinds := queryCSV(r, "kinds"); len(kinds) > 0 {
		input["kinds"] = kinds
	}
	if projectID := r.URL.Query().Get("projectId"); projectID != "" {
		input["projectId"] = projectID
	}
	return input
}

func requireServerID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("serverId")
	if !protocol.ValidOpaqueID(protocol.PrefixMCPServer, id) {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorInvalidInput, "The request could not be processed.", false))
		return "", false
	}
	return id, true
}

func mergeServerID(body map[string]any, serverID string) map[string]any {
	if body == nil {
		body = map[string]any{}
	}
	body["serverId"] = serverID
	return body
}

func asObjectList(raw any) []map[string]any {
	switch rows := raw.(type) {
	case []map[string]any:
		return rows
	case []any:
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			obj, _ := row.(map[string]any)
			if obj != nil {
				out = append(out, obj)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}

func projectObjects(raw any, keys ...string) []map[string]any {
	rows := asObjectList(raw)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, pickKeys(row, keys...))
	}
	return out
}

func projectMCPHeader(raw any) map[string]any {
	obj, _ := raw.(map[string]any)
	out := pickKeys(obj, "name", "kind", "secretRef", "value")
	kind, _ := out["kind"].(string)
	if kind != "literal" {
		delete(out, "value")
	}
	return out
}

func projectMCPServer(raw any) map[string]any {
	obj, _ := raw.(map[string]any)
	if obj == nil {
		return map[string]any{}
	}
	out := pickKeys(obj, "id", "name", "description", "transport", "endpoint", "enabled", "status", "toolCount", "lastConnectedAt", "lastError", "lastCheckedAt", "permissionDefault", "generation", "createdAt", "updatedAt")
	headers := make([]map[string]any, 0)
	for _, header := range asObjectList(obj["headers"]) {
		headers = append(headers, projectMCPHeader(header))
	}
	out["headers"] = headers
	return out
}

func projectMCPServers(raw any) []map[string]any {
	rows := asObjectList(raw)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, projectMCPServer(row))
	}
	return out
}

func projectKnowledgeItem(raw any) map[string]any {
	obj, _ := raw.(map[string]any)
	return pickKeys(obj, "id", "kind", "scope", "projectId", "workspaceId", "title", "content", "contentSha256", "journalType", "occurredAt", "generation", "createdAt", "updatedAt", "expiresAt", "tags", "provenance", "outboundLinks", "backlinks")
}

func projectKnowledgeItems(raw any) []map[string]any {
	rows := asObjectList(raw)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, projectKnowledgeItem(row))
	}
	return out
}

func projectKnowledgeHits(raw any) []map[string]any {
	rows := asObjectList(raw)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		hit := map[string]any{}
		for k, v := range row {
			if k == "item" {
				hit["item"] = projectKnowledgeItem(v)
				continue
			}
			hit[k] = v
		}
		out = append(out, hit)
	}
	return out
}

func projectKnowledgeLink(raw any) map[string]any {
	obj, _ := raw.(map[string]any)
	return pickKeys(obj, "id", "sourceId", "targetId", "relation", "origin", "generation", "createdAt")
}
