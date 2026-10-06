package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
	"github.com/bestagentkits/cloud-harness-mcp/internal/gateway"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const (
	defaultProbeMaxTools  = 500
	defaultProbeSchemaCap = 65_536
	schemaOmittedSuffix   = "(schema omitted: exceeds the gateway schema limit)"
)

func registerDashboardMCPProbe(mux *http.ServeMux, opts Options, sessions *Sessions) {
	mux.Handle("POST /api/v1/mcp-servers/{serverId}/test", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeMCPServer(w, r, opts, "test")
	})))))
	mux.Handle("POST /api/v1/mcp-servers/{serverId}/refresh", sessions.verify(requirePrincipal(requireJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeMCPServer(w, r, opts, "refresh")
	})))))
	mux.Handle("GET /api/v1/mcp-gateway", requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeMCPGatewayInfo(w, r, opts)
	})))
}

func writeMCPGatewayInfo(w http.ResponseWriter, r *http.Request, opts Options) {
	if _, ok := auth.IdentityFrom(r.Context()); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "session_ended", "message": "Your dashboard session ended."})
		return
	}
	var public any
	if len(opts.Security.PublicHosts) > 0 {
		public = "https://" + opts.Security.PublicHosts[0] + "/mcp-gateway"
	}
	mode := string(opts.Mode)
	if mode == "" {
		mode = string(auth.ModeOwnerBearer)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"endpoint":  "/mcp-gateway",
			"publicUrl": public,
			"authMode":  mode,
		},
	})
}

func probeMCPServer(w http.ResponseWriter, r *http.Request, opts Options, kind string) {
	serverID, ok := requireServerID(w, r)
	if !ok {
		return
	}
	if _, ok := decodeMutation(w, r); !ok {
		return
	}
	if opts.Runner == nil {
		writeDashboardFail(w, protocol.Fail(protocol.ErrorUnavailable, "The workspace service is temporarily unavailable.", true))
		return
	}
	result := discoverMCPServer(r.Context(), opts, serverID, kind)
	if !result.OK {
		writeDashboardFailOp(w, protocol.OpMCPServerConnectionResult, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": projectMCPConnection(result.Data), "truncated": result.Truncated})
}

func projectMCPConnection(data any) map[string]any {
	obj, _ := data.(map[string]any)
	out := pickKeys(obj, "status", "toolCount", "error")
	if _, ok := out["status"]; !ok {
		out["status"] = "error"
	}
	if _, ok := out["toolCount"]; !ok {
		out["toolCount"] = 0
	}
	if _, ok := out["error"]; !ok {
		out["error"] = nil
	}
	return out
}

func discoverMCPServer(ctx context.Context, opts Options, serverID, kind string) protocol.ToolResult {
	catalogRaw, _ := json.Marshal(map[string]any{"serverId": serverID})
	catalog := opts.Runner.CallInternal(ctx, protocol.OpMCPGatewayCatalog, catalogRaw)
	if !catalog.OK {
		return catalog
	}
	data, _ := catalog.Data.(map[string]any)
	var server map[string]any
	for _, row := range asObjectList(data["servers"]) {
		if id, _ := row["id"].(string); id == serverID {
			server = row
			break
		}
	}
	if server == nil {
		return protocol.Fail(protocol.ErrorNotFound, "unknown or inaccessible MCP server", false)
	}
	name, _ := server["name"].(string)
	outcome := probeDownstream(ctx, opts, serverID, server)
	_ = recordConnection(ctx, opts.Runner, serverID, outcome.status, outcome.err)
	body := map[string]any{
		"server":    name,
		"status":    outcome.status,
		"toolCount": outcome.toolCount,
		"error":     outcome.err,
	}
	if outcome.err != nil {
		return protocol.Success("MCP server "+name+" is not reachable", body)
	}
	message := "MCP server " + name + " is reachable"
	if kind == "refresh" {
		message = "Refreshed " + strconv.Itoa(outcome.toolCount) + " MCP tool(s)"
	}
	return protocol.Success(message, body)
}

type probeOutcome struct {
	status    string
	toolCount int
	err       any
}

func probeDownstream(ctx context.Context, opts Options, serverID string, server map[string]any) probeOutcome {
	credRaw, _ := json.Marshal(map[string]any{"serverId": serverID, "purpose": "connect"})
	creds := opts.Runner.CallInternal(ctx, protocol.OpMCPServerGetCredentials, credRaw)
	if !creds.OK {
		msg := creds.Message
		if creds.Error != nil && creds.Error.Message != "" {
			msg = creds.Error.Message
		}
		return probeOutcome{status: "error", err: sanitizeProbeError(msg, nil)}
	}
	view, _ := creds.Data.(map[string]any)
	if view["allowed"] != true {
		msg := "credential resolution was refused for this MCP server"
		return probeOutcome{status: "error", err: msg}
	}
	endpoint, _ := view["endpoint"].(string)
	if endpoint == "" {
		endpoint, _ = server["endpoint"].(string)
	}
	headers := map[string]string{}
	if raw, ok := view["headers"].(map[string]string); ok {
		headers = raw
	} else if raw, ok := view["headers"].(map[string]any); ok {
		for k, v := range raw {
			if s, ok := v.(string); ok {
				headers[k] = s
			}
		}
	}
	secrets := make([]string, 0, len(headers))
	for _, v := range headers {
		if len(v) >= 4 {
			secrets = append(secrets, v)
		}
	}
	validated, err := gateway.ValidateEndpoint(endpoint, gateway.EndpointOptions{
		AllowInsecureHTTP:     opts.MCPGatewayAllowInsecureHTTP,
		AllowPrivateEndpoints: opts.MCPGatewayAllowPrivateEndpoints,
		Resolve:               opts.MCPGatewayResolve,
	})
	if err != nil {
		return probeOutcome{status: "error", err: sanitizeProbeError(err.Error(), secrets)}
	}
	client := gateway.DownstreamClient{
		Endpoint:  validated.URL,
		Addresses: validated.Addresses,
		Headers:   headers,
	}
	tools, fail, ok := client.ListTools(ctx)
	if !ok {
		msg := fail.Message
		if fail.Error != nil && fail.Error.Message != "" {
			msg = fail.Error.Message
		}
		return probeOutcome{status: "error", err: sanitizeProbeError(msg, secrets)}
	}
	normalized := normalizeUpstreamTools(asString(server["name"]), tools)
	replace, _ := json.Marshal(map[string]any{
		"serverId": serverID,
		"status":   "connected",
		"cap":      defaultProbeMaxTools,
		"tools":    normalized,
	})
	replaced := opts.Runner.CallInternal(ctx, protocol.OpMCPServerReplaceTools, replace)
	if !replaced.OK {
		msg := replaced.Message
		if replaced.Error != nil && replaced.Error.Message != "" {
			msg = replaced.Error.Message
		}
		return probeOutcome{status: "error", err: sanitizeProbeError(msg, secrets)}
	}
	return probeOutcome{status: "connected", toolCount: len(normalized), err: nil}
}

func recordConnection(ctx context.Context, runner *mcp.RunnerClient, serverID, status string, err any) protocol.ToolResult {
	var message *string
	if s, ok := err.(string); ok && s != "" {
		message = &s
	}
	raw, _ := json.Marshal(map[string]any{
		"serverId": serverID,
		"status":   status,
		"error":    message,
	})
	return runner.CallInternal(ctx, protocol.OpMCPServerConnectionResult, raw)
}

func normalizeUpstreamTools(serverName string, tools []gateway.UpstreamTool) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	seen := map[string]struct{}{}
	accepted := 0
	for _, tool := range tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" {
			continue
		}
		qualified := protocol.QualifiedToolName(serverName, name)
		if _, dup := seen[qualified]; dup {
			continue
		}
		seen[qualified] = struct{}{}
		overflow := accepted >= defaultProbeMaxTools
		accepted++
		schema := tool.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		schemaJSON, err := json.Marshal(schema)
		omit := err != nil || len(schemaJSON) > defaultProbeSchemaCap
		desc := tool.Description
		if omit {
			desc = omitSchemaDescription(desc)
			schema = map[string]any{"type": "object"}
		} else if len(desc) > 2_000 {
			desc = desc[:2_000]
		}
		availability := "available"
		if overflow || omit {
			availability = "unavailable"
		}
		out = append(out, map[string]any{
			"upstreamName": name,
			"description":  desc,
			"inputSchema":  schema,
			"annotations":  tool.Annotations,
			"availability": availability,
			"schemaBytes":  len(schemaJSON),
		})
	}
	return out
}

func omitSchemaDescription(description string) string {
	room := 2_000 - len(schemaOmittedSuffix) - 1
	if room < 0 {
		return schemaOmittedSuffix
	}
	base := strings.TrimSpace(truncateRunes(description, room))
	if base == "" {
		return schemaOmittedSuffix
	}
	return base + " " + schemaOmittedSuffix
}

func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func sanitizeProbeError(message string, secrets []string) string {
	out := message
	if len(out) > 2_000 {
		out = out[:2_000]
	}
	for _, secret := range secrets {
		if len(secret) >= 4 {
			out = strings.ReplaceAll(out, secret, "[REDACTED_SECRET]")
		}
	}
	return out
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
