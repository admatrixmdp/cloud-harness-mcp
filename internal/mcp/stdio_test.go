package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestServeStdioListsToolsAndConfinesWorkspace(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files_read","arguments":{"path":"hello.txt"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files_read","arguments":{"path":"../etc/passwd"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"workspace_open","arguments":{}}}
`)
	var out bytes.Buffer
	if err := ServeStdio(context.Background(), in, &out, HandlerOptions{Local: LocalBackend{Root: root}}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("responses=%d body=%s", len(lines), out.String())
	}
	var listed struct {
		Result struct {
			Tools []ToolSpec `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Result.Tools) != len(protocol.AllOperations) {
		t.Fatalf("listed %d", len(listed.Result.Tools))
	}
	var read struct {
		Result CallToolResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &read); err != nil {
		t.Fatal(err)
	}
	if read.Result.IsError || !strings.Contains(read.Result.Content[0]["text"].(string), "hi") {
		t.Fatalf("%+v", read.Result)
	}
	var escaped struct {
		Result CallToolResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &escaped); err != nil {
		t.Fatal(err)
	}
	if !escaped.Result.IsError || escaped.Result.StructuredContent.Error == nil || escaped.Result.StructuredContent.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("escape: %+v", escaped.Result)
	}
	var open struct {
		Result CallToolResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[3]), &open); err != nil {
		t.Fatal(err)
	}
	if !open.Result.IsError || !strings.Contains(open.Result.StructuredContent.Message, "--workspace") {
		t.Fatalf("open: %+v", open.Result)
	}
}
