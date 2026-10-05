package protocol

import (
	"encoding/json"
	"testing"
)

func TestToolResultJSONEnvelope(t *testing.T) {
	raw, err := json.Marshal(Success("opened", map[string]string{"workspaceId": "ws_abcdefghijklmnopqrst"}))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ok", "message", "truncated"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing required envelope field %q in %s", key, raw)
		}
	}
	if got["ok"] != true {
		t.Fatalf("ok: %v", got["ok"])
	}
}

func TestFailEnvelope(t *testing.T) {
	raw, err := json.Marshal(Fail(ErrorDependencyEgressUnavailable, "attestation failed", false))
	if err != nil {
		t.Fatal(err)
	}
	var got ToolResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.OK || got.Error == nil || got.Error.Code != ErrorDependencyEgressUnavailable {
		t.Fatalf("unexpected fail envelope: %+v", got)
	}
}

func TestValidOpaqueID(t *testing.T) {
	if !ValidOpaqueID(PrefixWorkspace, "ws_abcdefghijklmnopqrst") {
		t.Fatal("expected valid workspace id")
	}
	if ValidOpaqueID(PrefixWorkspace, "ws_short") {
		t.Fatal("short id must be rejected")
	}
	if ValidOpaqueID(PrefixWorkspace, "op_abcdefghijklmnopqrst") {
		t.Fatal("wrong prefix must be rejected")
	}
}

func TestNetworkProfile(t *testing.T) {
	if !DependencyAccess.Valid() || !NetworkNone.Valid() {
		t.Fatal("shipped profiles must be valid")
	}
	if NetworkProfile("bridge").Valid() {
		t.Fatal("raw bridge must not be selectable")
	}
}
