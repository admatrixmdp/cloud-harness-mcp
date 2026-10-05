package mcp

import (
	"context"
	"encoding/json"

	"github.com/bestagentkits/cloud-harness-mcp/internal/gateway"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// Dispatcher executes one coding-harness operation. HTTP uses RunnerClient;
// stdio uses a local workspace backend.
type Dispatcher interface {
	Call(ctx context.Context, op protocol.Operation, input json.RawMessage) protocol.ToolResult
}

func serveRPC(ctx context.Context, req rpcRequest, opts HandlerOptions, tools []ToolSpec, gatewayReg *gateway.Registry, coding bool) rpcResponse {
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		name := "cloud-harness-mcp"
		if !coding {
			name = "cloud-harness-mcp-gateway"
		}
		resp.Result = map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": name, "version": "go-port"},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools}
	case "tools/call":
		if coding {
			resp.Result = dispatchCall(ctx, opts, req.Params)
		} else {
			resp.Result = dispatchGateway(gatewayReg, req.Params)
		}
	default:
		resp.Error = &rpcError{Code: -32601, Message: "method not found"}
	}
	return resp
}

func dispatchCall(ctx context.Context, opts HandlerOptions, params json.RawMessage) CallToolResult {
	var p callParams
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		return ResultToMCP(protocol.Fail(protocol.ErrorInvalidInput, "tools/call requires name", false))
	}
	op := protocol.Operation(p.Name)
	if !op.Known() {
		return ResultToMCP(protocol.Fail(protocol.ErrorInvalidInput, "unknown tool", false))
	}
	if opts.Local != nil {
		return ResultToMCP(opts.Local.Call(ctx, op, p.Arguments))
	}
	if opts.Runner == nil {
		return ResultToMCP(protocol.Fail(protocol.ErrorUnavailable, "Runner is unavailable", true))
	}
	return ResultToMCP(opts.Runner.Call(ctx, op, p.Arguments))
}

func dispatchGateway(reg *gateway.Registry, params json.RawMessage) CallToolResult {
	if reg == nil {
		reg = gateway.NewRegistry()
	}
	var p callParams
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		return ResultToMCP(protocol.Fail(protocol.ErrorInvalidInput, "tools/call requires name", false))
	}
	args := map[string]any{}
	if len(p.Arguments) > 0 {
		_ = json.Unmarshal(p.Arguments, &args)
	}
	return ResultToMCP(reg.Dispatch(p.Name, args))
}
