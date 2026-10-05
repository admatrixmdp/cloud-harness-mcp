package secrets

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestKeyringBindsAssociatedData(t *testing.T) {
	ring, err := NewKeyring(1, []KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{1}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	ctx := Context{PrincipalID: "principal-a", EnvironmentID: "environment-a", Name: "API_TOKEN", Version: 1}
	enc, err := ring.EncryptString("highly-sensitive-value", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Verify(enc, ctx); err != nil {
		t.Fatal(err)
	}
	got, err := ring.DecryptString(enc, ctx)
	if err != nil || got != "highly-sensitive-value" {
		t.Fatalf("%q %v", got, err)
	}
	if err := ring.Verify(enc, Context{PrincipalID: "principal-b", EnvironmentID: ctx.EnvironmentID, Name: ctx.Name, Version: ctx.Version}); err == nil {
		t.Fatal("principal mismatch must fail")
	}
	if err := ring.Verify(enc, Context{PrincipalID: ctx.PrincipalID, EnvironmentID: "environment-b", Name: ctx.Name, Version: ctx.Version}); err == nil {
		t.Fatal("environment mismatch must fail")
	}
	if err := ring.Verify(enc, Context{PrincipalID: ctx.PrincipalID, EnvironmentID: ctx.EnvironmentID, Name: "OTHER_TOKEN", Version: ctx.Version}); err == nil {
		t.Fatal("name mismatch must fail")
	}
	if err := ring.Verify(enc, Context{PrincipalID: ctx.PrincipalID, EnvironmentID: ctx.EnvironmentID, Name: ctx.Name, Version: 2}); err == nil {
		t.Fatal("version mismatch must fail")
	}
}

func TestKeyringRotationAndUnknownVersion(t *testing.T) {
	old, err := NewKeyring(1, []KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{1}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context{PrincipalID: "principal-a", EnvironmentID: "environment-a", Name: "API_TOKEN", Version: 1}
	enc, err := old.EncryptString("rotate-me", ctx)
	if err != nil {
		t.Fatal(err)
	}
	old.Close()

	mixed, err := NewKeyring(2, []KeyConfig{
		{Version: 1, Key: bytes.Repeat([]byte{1}, 32)},
		{Version: 2, Key: bytes.Repeat([]byte{2}, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mixed.Close)
	if err := mixed.Verify(enc, ctx); err != nil {
		t.Fatal(err)
	}
	next, err := mixed.Reencrypt(enc, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if next.KeyVersion != 2 {
		t.Fatalf("key version %d", next.KeyVersion)
	}

	activeOnly, err := NewKeyring(2, []KeyConfig{{Version: 2, Key: bytes.Repeat([]byte{2}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(activeOnly.Close)
	if err := activeOnly.Verify(enc, ctx); err == nil || !strings.Contains(err.Error(), "unknown secret key version 1") {
		t.Fatalf("expected unknown version, got %v", err)
	}
}

func TestKeyringRejectsBadKeys(t *testing.T) {
	if _, err := NewKeyring(2, []KeyConfig{{Version: 1, Key: make([]byte, 32)}}); err == nil {
		t.Fatal("missing active version")
	}
	if _, err := NewKeyring(1, []KeyConfig{{Version: 1, Key: make([]byte, 31)}}); err == nil {
		t.Fatal("short key")
	}
	if _, err := NewKeyring(1, []KeyConfig{
		{Version: 1, Key: make([]byte, 32)},
		{Version: 1, Key: make([]byte, 32)},
	}); err == nil {
		t.Fatal("duplicate version")
	}
}

func TestAssociatedDataMatchesTypeScriptJSON(t *testing.T) {
	ctx := Context{PrincipalID: "principal-a", EnvironmentID: "environment-a", Name: "API_TOKEN", Version: 1}
	got := associatedData(ctx)
	want, _ := json.Marshal([]any{"principal-a", "environment-a", "API_TOKEN", 1})
	if !bytes.Equal(got, want) || string(got) != `["principal-a","environment-a","API_TOKEN",1]` {
		t.Fatalf("%s", got)
	}
}

func TestErrorsDoNotEchoPlaintext(t *testing.T) {
	ring, err := NewKeyring(1, []KeyConfig{{Version: 1, Key: bytes.Repeat([]byte{1}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	ctx := Context{PrincipalID: "p", EnvironmentID: "e", Name: "N", Version: 1}
	enc, err := ring.EncryptString("super-secret-plaintext", ctx)
	if err != nil {
		t.Fatal(err)
	}
	enc.AuthTag[0] ^= 0xff
	err = ring.Verify(enc, ctx)
	if err == nil {
		t.Fatal("tamper accepted")
	}
	if strings.Contains(err.Error(), "super-secret-plaintext") {
		t.Fatalf("plaintext leaked: %v", err)
	}
}
