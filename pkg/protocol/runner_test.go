package protocol

import (
	"encoding/json"
	"testing"
)

func TestPrincipalOwnerIDPrefersExternalPrincipal(t *testing.T) {
	raw, _ := json.Marshal(ExternalPrincipal{Kind: PrincipalExternal, Issuer: "https://iss", Subject: "user-1"})
	got := PrincipalOwnerID(RunnerRequest{OwnerID: "legacy", Principal: raw})
	if got != "https://iss\x00user-1" {
		t.Fatalf("%q", got)
	}
}

func TestPrincipalOwnerIDOwnerKind(t *testing.T) {
	raw, _ := json.Marshal(OwnerPrincipal{Kind: PrincipalOwner, OwnerID: "owner-a"})
	got := PrincipalOwnerID(RunnerRequest{OwnerID: "legacy", Principal: raw})
	if got != "owner-a" {
		t.Fatalf("%q", got)
	}
}
