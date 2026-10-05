package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// FormatToolResultText is the MCP text content for a ToolResult.
func FormatToolResultText(result protocol.ToolResult) string {
	sections := make([]string, 0, 4)
	if result.Message != "" {
		sections = append(sections, result.Message)
	}
	if result.Data != nil {
		if raw, err := json.Marshal(result.Data); err == nil && string(raw) != "null" && string(raw) != "{}" && string(raw) != "[]" {
			sections = append(sections, string(raw))
		}
	}
	if result.Error != nil {
		sections = append(sections, fmt.Sprintf("Error [%s]: %s (retryable: %v)", result.Error.Code, result.Error.Message, result.Error.Retryable))
	}
	if result.Truncated && result.Cursor != "" {
		sections = append(sections, "[truncated — next cursor: "+result.Cursor+"]")
	} else if result.Truncated {
		sections = append(sections, "[truncated — narrow the request]")
	} else if result.Cursor != "" {
		sections = append(sections, "[next cursor: "+result.Cursor+"]")
	}
	return strings.Join(sections, "\n\n")
}

// CallToolResult is the MCP tools/call payload.
type CallToolResult struct {
	Content           []map[string]any    `json:"content"`
	StructuredContent protocol.ToolResult `json:"structuredContent"`
	IsError           bool                `json:"isError"`
}

// ResultToMCP wraps a ToolResult as MCP tools/call output.
func ResultToMCP(result protocol.ToolResult) CallToolResult {
	return CallToolResult{
		Content:           []map[string]any{{"type": "text", "text": FormatToolResultText(result)}},
		StructuredContent: result,
		IsError:           !result.OK,
	}
}
