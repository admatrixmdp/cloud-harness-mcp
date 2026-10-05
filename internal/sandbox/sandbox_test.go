package sandbox

import (
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestDefaultIsDependencyAccess(t *testing.T) {
	if DefaultNetworkProfile != protocol.DependencyAccess {
		t.Fatalf("default = %q, want dependency-access", DefaultNetworkProfile)
	}
	if protocol.NetworkProfile("bridge").Valid() {
		t.Fatal("bridge must not be a selectable profile")
	}
}
