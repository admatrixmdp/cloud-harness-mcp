package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// RunnerClient is the API→runner RPC client. The API never holds a Docker socket.
type RunnerClient struct {
	BaseURL      string
	ServiceToken string
	HTTP         *http.Client
	Timeout      time.Duration
	OwnerID      string
}

func (c *RunnerClient) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *RunnerClient) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 15 * time.Second
}

// Ready probes runner /healthz.
func (c *RunnerClient) Ready(ctx context.Context) bool {
	if c.BaseURL == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/healthz", nil)
	if err != nil {
		return false
	}
	res, err := c.http().Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode == http.StatusOK
}

// Call posts /v1/operations and returns the ToolResult envelope.
func (c *RunnerClient) Call(ctx context.Context, op protocol.Operation, input json.RawMessage) protocol.ToolResult {
	if c.BaseURL == "" {
		return protocol.Fail(protocol.ErrorUnavailable, "Runner is unavailable", true)
	}
	if input == nil {
		input = json.RawMessage(`{}`)
	}
	body, err := json.Marshal(protocol.RunnerRequest{
		Version:   2,
		OwnerID:   c.OwnerID,
		Operation: op,
		Input:     input,
	})
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, "failed to encode runner request", false)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/operations", bytes.NewReader(body))
	if err != nil {
		return protocol.Fail(protocol.ErrorUnavailable, "Runner is unavailable", true)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.ServiceToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.ServiceToken)
	}
	res, err := c.http().Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return protocol.Fail(protocol.ErrorTimeout, "Runner request timed out", true)
		}
		return protocol.Fail(protocol.ErrorUnavailable, "Runner is unavailable", true)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return protocol.Fail(protocol.ErrorUnavailable, "Runner is unavailable", true)
	}
	var result protocol.ToolResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return protocol.Fail(protocol.ErrorUnavailable, fmt.Sprintf("Runner returned invalid envelope (HTTP %d)", res.StatusCode), true)
	}
	return result
}
