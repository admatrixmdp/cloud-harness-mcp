package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
)

// ServeStdio reads newline-delimited JSON-RPC from r and writes one response
// per request to w. It is the local `--transport stdio` composition root.
func ServeStdio(ctx context.Context, r io.Reader, w io.Writer, opts HandlerOptions) error {
	tools := ToolList()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	enc := json.NewEncoder(w)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			if err := enc.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}}); err != nil {
				return err
			}
			continue
		}
		if err := enc.Encode(serveRPC(ctx, req, opts, tools, nil, true)); err != nil {
			return err
		}
	}
	return scanner.Err()
}
