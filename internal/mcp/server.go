package mcp

import (
	"encoding/json"
	"net/http"

	"github.com/bestagentkits/cloud-harness-mcp/internal/gateway"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// ToolSpec is the MCP tools/list entry for one coding-harness operation.
type ToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

// ToolList is the public MCP catalog derived from pkg/protocol.
func ToolList() []ToolSpec {
	out := make([]ToolSpec, 0, len(protocol.AllOperations))
	for _, op := range protocol.AllOperations {
		out = append(out, ToolSpec{
			Name:        string(op),
			Description: string(op),
			InputSchema: map[string]any{"type": "object"},
			Annotations: map[string]any{
				"readOnlyHint":    op.ReadOnly(),
				"destructiveHint": op.Destructive(),
				"openWorldHint":   op.OpenWorld(),
			},
		})
	}
	return out
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// HandlerOptions configure the MCP JSON-RPC surface.
type HandlerOptions struct {
	Runner          *RunnerClient
	Local           Dispatcher
	Gateway         *gateway.Registry
	GatewayEndpoint gateway.EndpointOptions
}

// Handler serves Streamable-HTTP JSON-RPC: initialize, ping, tools/list, tools/call.
func Handler() http.Handler {
	return HandlerWith(HandlerOptions{})
}

// HandlerWith injects a runner client for tools/call.
func HandlerWith(opts HandlerOptions) http.Handler {
	tools := ToolList()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ct := r.Header.Get("Content-Type")
		if ct != "" && ct != "application/json" && ct != "application/json; charset=utf-8" {
			http.Error(w, `{"error":"unsupported_media_type"}`, http.StatusUnsupportedMediaType)
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			return
		}
		writeRPC(w, serveRPC(r.Context(), req, opts, tools, opts.Gateway, true))
	})
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// GatewayHandler serves the constant five-tool /mcp-gateway catalog.
func GatewayHandler() http.Handler {
	return GatewayHandlerWith(HandlerOptions{})
}

// GatewayHandlerWith injects a downstream catalog or live runner. tools/list stays five tools.
func GatewayHandlerWith(opts HandlerOptions) http.Handler {
	reg := opts.Gateway
	if reg == nil {
		reg = gateway.NewRegistry()
	}
	tools := make([]ToolSpec, 0, len(protocol.GatewayTools))
	for _, name := range protocol.GatewayTools {
		tools = append(tools, ToolSpec{
			Name:        name,
			InputSchema: map[string]any{"type": "object"},
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			return
		}
		writeRPC(w, serveRPC(r.Context(), req, opts, tools, reg, false))
	})
}
