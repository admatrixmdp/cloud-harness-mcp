package auth

import (
	"strings"
	"testing"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestParseAndVerifyAPIKey(t *testing.T) {
	id := "apk_abcdefghijklmnopqrstuvwx"
	secret := EncodeRandom(make([]byte, 32))
	value := "chm_key_" + id + "." + secret
	if !protocol.ValidAPIKeyValue(value) {
		t.Fatalf("fixture value rejected: %s", value)
	}
	gotID, gotSecret, ok := ParseAPIKey(value)
	if !ok || gotID != id || gotSecret != secret {
		t.Fatalf("%s %s %v", gotID, gotSecret, ok)
	}
	hash := HashSecret(secret)
	if !VerifySecret(secret, hash) {
		t.Fatal("verify failed")
	}
	if VerifySecret("wrong-secret-material-value-xxxxx", hash) {
		t.Fatal("wrong secret accepted")
	}
	prefix := DisplayPrefix(id)
	if strings.Contains(prefix, secret) {
		t.Fatal("display prefix leaked secret")
	}
}

func TestRejectsMalformedKey(t *testing.T) {
	if _, _, ok := ParseAPIKey("not-a-key"); ok {
		t.Fatal("accepted")
	}
	if protocol.ValidAPIKeyValue("chm_key_apk_short.secret") {
		t.Fatal("short id accepted")
	}
}
