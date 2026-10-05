package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

const redirectRefused = "downstream MCP endpoint returned an HTTP redirect; HTTP redirects are refused, configure the final URL"

// DownstreamClient posts tools/call to a validated MCP HTTP endpoint.
// Credentials attach only to the configured origin+pathname. Redirects fail closed.
// Addresses, when set, pin the TCP dial so a rebinding resolver cannot steal the request.
type DownstreamClient struct {
	Endpoint  *url.URL
	Addresses []net.IP
	Headers   map[string]string
	HTTP      *http.Client
	Timeout   time.Duration
}

func (c DownstreamClient) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 30 * time.Second
}

func (c DownstreamClient) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if len(c.Addresses) > 0 {
		transport.DialContext = PinnedDialContext(c.Addresses)
	}
	return &http.Client{
		Timeout:   c.timeout(),
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
}

var errRedirect = fmt.Errorf("%s", redirectRefused)

func sanitizeText(text string, secrets []string) string {
	out := text
	if len(out) > 8192 {
		out = out[:8192]
	}
	for _, secret := range secrets {
		if len(secret) < 4 {
			continue
		}
		out = strings.ReplaceAll(out, secret, "[REDACTED_SECRET]")
	}
	return out
}

func secretsFrom(headers map[string]string) []string {
	out := make([]string, 0, len(headers))
	for _, v := range headers {
		if len(v) >= 4 {
			out = append(out, v)
		}
	}
	return out
}

func attachHeaders(req *http.Request, endpoint *url.URL, headers map[string]string) {
	if endpoint == nil || !IsConfiguredEndpoint(req.URL.String(), endpoint) {
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

// Call posts one MCP tools/call. Denied tools never reach this client.
func (c DownstreamClient) Call(ctx context.Context, tool string, arguments map[string]any) protocol.ToolResult {
	if c.Endpoint == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "downstream MCP execute is not wired in this Go-port slice", true)
	}
	if arguments == nil {
		arguments = map[string]any{}
	}
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": arguments},
	})
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, "failed to encode downstream call", false)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return protocol.Fail(protocol.ErrorUnavailable, "downstream MCP is unavailable", true)
	}
	req.Header.Set("Content-Type", "application/json")
	attachHeaders(req, c.Endpoint, c.Headers)
	res, err := c.http().Do(req)
	if err != nil {
		msg := sanitizeText(err.Error(), secretsFrom(c.Headers))
		if strings.Contains(err.Error(), redirectRefused) || (strings.Contains(msg, "redirect") && strings.Contains(msg, "refused")) {
			return protocol.Fail(protocol.ErrorUnavailable, redirectRefused, false)
		}
		return protocol.Fail(protocol.ErrorUnavailable, "downstream MCP is unavailable", true)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return protocol.Fail(protocol.ErrorUnavailable, redirectRefused, false)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return protocol.Fail(protocol.ErrorUnavailable, "downstream MCP is unavailable", true)
	}
	redacted := sanitizeText(string(raw), secretsFrom(c.Headers))
	var rpc struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(redacted), &rpc); err != nil {
		return protocol.Fail(protocol.ErrorUnavailable, "downstream MCP returned an invalid envelope", true)
	}
	if rpc.Error != nil {
		return protocol.Fail(protocol.ErrorExecutionFailed, sanitizeText(rpc.Error.Message, secretsFrom(c.Headers)), false)
	}
	var result protocol.ToolResult
	if len(rpc.Result) > 0 {
		if err := json.Unmarshal(rpc.Result, &result); err == nil && (result.OK || result.Error != nil) {
			return result
		}
	}
	return protocol.Success("downstream tool result", map[string]any{"raw": json.RawMessage(redacted)})
}
