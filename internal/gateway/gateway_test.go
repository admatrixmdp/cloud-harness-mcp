package gateway

import "testing"

func TestConstantToolSet(t *testing.T) {
	if len(Tools) != 5 {
		t.Fatalf("gateway tools = %d, want 5", len(Tools))
	}
	seen := map[string]bool{}
	for _, name := range Tools {
		if seen[name] {
			t.Fatalf("duplicate tool %q", name)
		}
		seen[name] = true
	}
	for _, want := range []string{"search", "inspect", "execute", "permissions", "status"} {
		if !seen[want] {
			t.Fatalf("missing tool %q", want)
		}
	}
}
