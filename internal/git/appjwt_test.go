package git

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func TestAppJWTClaimsAndMintStdinIsolation(t *testing.T) {
	pemBytes := testPEM(t)
	cfg := AppConfig{AppID: "123456", InstallationID: "789", PrivateKey: pemBytes}
	now := time.Unix(1_700_000_000, 0).UTC()
	jwt, err := AppJWT(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jwt, "BEGIN") {
		t.Fatal("PEM leaked into JWT")
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("parts=%d", len(parts))
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "123456" {
		t.Fatalf("iss=%v", claims["iss"])
	}
	exp := int64(claims["exp"].(float64))
	iat := int64(claims["iat"].(float64))
	if exp-iat > 10*60 {
		t.Fatalf("jwt longer than 10m: %d", exp-iat)
	}

	req, err := MintRequest(cfg, "cloud-harness-mcp", now)
	if err != nil {
		t.Fatal(err)
	}
	if RequestLeaksMaterial(req, pemBytes, "ghs_not-a-real-token") {
		t.Fatal("mint request leaked material")
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") {
		t.Fatal("missing bearer jwt")
	}
	if strings.Contains(req.URL.String(), "ghs_") {
		t.Fatal("token in URL")
	}

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") == "" {
			t.Fatal("jwt missing on mint POST")
		}
		body := `{"token":"ghs_this-is-not-a-real-token-value","expires_at":"2024-01-01T00:10:00Z"}`
		return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	minted, err := MintInstallationToken(cfg, "cloud-harness-mcp", client, now)
	if err != nil {
		t.Fatal(err)
	}
	if minted.Token == "" {
		t.Fatal("empty token")
	}
	args := CloneArgs(HelperSpec{
		Name: "chm-clone", Image: "cloud-harness-executor:local",
		WorkspaceID: "ws_abcdefghijklmnopqrstuvwx", JobPath: "/jobs/ws",
		RepositoryURL: "https://github.com/bestagentkits/cloud-harness-mcp",
	})
	if ArgsContainSecret(args, minted.Token) {
		t.Fatal("minted token leaked into docker argv")
	}
	if minted.Stdin() != minted.Token {
		t.Fatal("stdin must carry the token")
	}
	if RedactToken("token="+minted.Token, minted.Token) != "token=[redacted]" {
		t.Fatal("redact")
	}
}

func TestMintRepositoryTokenUnconfiguredIsNoop(t *testing.T) {
	u, err := ValidateRepositoryURL("https://github.com/owner/repo.git", []string{"github.com"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := MintRepositoryToken(AppConfig{}, u, nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "" {
		t.Fatal("unconfigured GitHub App must not mint")
	}
}

func TestMintRepositoryTokenRejectsAmbiguousPathBeforeHTTP(t *testing.T) {
	u, err := ValidateRepositoryURL("https://github.com/owner/repo/extra.git", []string{"github.com"})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}
	_, err = MintRepositoryToken(AppConfig{AppID: "1", InstallationID: "2", PrivateKey: testPEM(t)}, u, client, time.Unix(1_700_000_000, 0))
	if err == nil {
		t.Fatal("ambiguous path must fail")
	}
	if called {
		t.Fatal("HTTP must not run before path validation")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
