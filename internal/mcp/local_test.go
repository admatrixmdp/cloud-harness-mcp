package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestLocalBackendRejectsRemoteOnlyAndGitWithoutFlags(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := LocalBackend{Root: root}
	got := b.Call(context.Background(), protocol.OpWorkspaceOpen, json.RawMessage(`{}`))
	if got.OK || got.Error.Code != protocol.ErrorInvalidInput {
		t.Fatalf("open: %+v", got)
	}
	got = b.Call(context.Background(), protocol.OpGitPush, json.RawMessage(`{}`))
	if got.OK || got.Error.Code != protocol.ErrorForbidden {
		t.Fatalf("push without flag: %+v", got)
	}
	listed := b.Call(context.Background(), protocol.OpFilesList, json.RawMessage(`{"path":"."}`))
	if !listed.OK {
		t.Fatalf("list: %+v", listed)
	}
	moved := b.Call(context.Background(), protocol.OpFilesWriteBatch, json.RawMessage(`{"files":[{"path":"b.txt","content":"two"}]}`))
	if !moved.OK {
		t.Fatalf("batch: %+v", moved)
	}
}
