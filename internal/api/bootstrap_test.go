package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/auth"
	"github.com/bestagentkits/cloud-harness-mcp/internal/mcp"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

func TestProductionOptionsAccessForbidsBearer(t *testing.T) {
	_, err := ProductionOptions(func(name string) string {
		switch name {
		case "AUTH_MODE":
			return "cloudflare-access"
		case "MCP_BEARER_TOKEN":
			return "owner-secret"
		case "CLOUDFLARE_ACCESS_ISSUER":
			return "https://team.cloudflareaccess.com"
		case "CLOUDFLARE_ACCESS_AUDIENCE":
			return "aud"
		case "CLOUDFLARE_ACCESS_JWKS_URL":
			return "https://team.cloudflareaccess.com/cdn-cgi/access/certs"
		default:
			return ""
		}
	})
	if err == nil {
		t.Fatal("bearer must be forbidden in Access mode")
	}
}

func TestProductionOptionsOwnerBearerForbidsAccessSettings(t *testing.T) {
	_, err := ProductionOptions(func(name string) string {
		switch name {
		case "MCP_BEARER_TOKEN":
			return "owner-secret"
		case "CLOUDFLARE_ACCESS_ISSUER":
			return "https://team.cloudflareaccess.com"
		default:
			return ""
		}
	})
	if err == nil {
		t.Fatal("Access settings forbidden in owner-bearer")
	}
}

func signAccess(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAccessJWTForwardsExternalPrincipalAndIgnoresOpaqueBearer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1", "n": n, "e": e}},
		})
	}))
	t.Cleanup(jwks.Close)
	var captured protocol.RunnerRequest
	runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "eyJ") {
			t.Fatal("JWT must not be forwarded to the runner")
		}
		_ = json.Unmarshal(raw, &captured)
		_ = json.NewEncoder(w).Encode(protocol.Success("ok", map[string]any{}))
	}))
	t.Cleanup(runner.Close)
	now := time.Unix(1_700_000_000, 0)
	verifier := auth.NewAccessVerifier(auth.AccessConfig{
		Issuer: "https://issuer.example", Audience: "aud-1", JWKSURL: jwks.URL,
	}, jwks.Client(), func() time.Time { return now })
	srv := httptest.NewServer(Handler(Options{
		Mode:           auth.ModeCloudflareAccess,
		BearerToken:    "owner-secret",
		AccessVerifier: verifier,
		Runner:         &mcp.RunnerClient{BaseURL: runner.URL, OwnerID: "static-owner"},
	}))
	t.Cleanup(srv.Close)
	token := signAccess(t, key, "k1", map[string]any{
		"iss": "https://issuer.example", "aud": "aud-1", "type": "app",
		"sub": "user-1", "exp": now.Unix() + 60, "nbf": now.Unix() - 1, "email": "a@b.c",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"workspace_list","arguments":{}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer owner-secret")
	req.Header.Set("Cf-Access-Jwt-Assertion", token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	if captured.OwnerID != "https://issuer.example\x00user-1" {
		t.Fatalf("owner %q", captured.OwnerID)
	}
	var p protocol.ExternalPrincipal
	if err := json.Unmarshal(captured.Principal, &p); err != nil || p.Kind != protocol.PrincipalExternal || p.Subject != "user-1" {
		t.Fatalf("principal %s", captured.Principal)
	}
	if strings.Contains(string(captured.Principal), token) {
		t.Fatal("assertion leaked onto runner RPC")
	}
}

func TestAccessModeMissingAssertionIsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{
		Mode:           auth.ModeCloudflareAccess,
		AccessVerifier: auth.NewAccessVerifier(auth.AccessConfig{Issuer: "https://iss", Audience: "aud", JWKSURL: "https://iss/jwks"}, nil, nil),
	}))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer owner-secret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", res.StatusCode)
	}
	raw, _ := io.ReadAll(res.Body)
	if strings.Contains(string(raw), "owner-secret") {
		t.Fatal("token leaked")
	}
}

func TestAPIKeyGatewayRequiresServiceAssertionAndManagedKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1", "n": n, "e": e}},
		})
	}))
	t.Cleanup(jwks.Close)
	now := time.Unix(1_700_000_000, 0)
	serviceSubject := "cf-service:" + base64.RawURLEncoding.EncodeToString([]byte("worker-service-client-id"))
	mainVerifier := auth.NewAccessVerifier(auth.AccessConfig{
		Issuer: "https://issuer.example", Audience: "main-aud", JWKSURL: jwks.URL,
	}, jwks.Client(), func() time.Time { return now })
	gatewayVerifier := auth.NewAccessVerifier(auth.AccessConfig{
		Issuer: "https://issuer.example", Audience: "gateway-aud", JWKSURL: jwks.URL,
	}, jwks.Client(), func() time.Time { return now })

	apiKey := "chm_key_apk_" + strings.Repeat("a", 24) + "." + strings.Repeat("b", 43)
	var captured protocol.RunnerRequest
	var sawSecret bool
	runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), apiKey) && r.URL.Path != "/v1/internal/api-keys" {
			sawSecret = true
		}
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.URL.Path == "/v1/internal/api-keys" {
			var body struct {
				APIKey string `json:"apiKey"`
			}
			_ = json.Unmarshal(raw, &body)
			if body.APIKey != apiKey {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "authentication_failed"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"data": map[string]any{
					"principal": map[string]any{"kind": "external", "issuer": "https://issuer.example", "subject": "human-subject"},
					"keyId":     "apk_" + strings.Repeat("a", 24),
				},
			})
			return
		}
		_ = json.Unmarshal(raw, &captured)
		_ = json.NewEncoder(w).Encode(protocol.Success("ok", map[string]any{}))
	}))
	t.Cleanup(runner.Close)

	srv := httptest.NewServer(Handler(Options{
		Mode:                        auth.ModeCloudflareAccess,
		AccessVerifier:              mainVerifier,
		APIKeyAuthEnabled:           true,
		APIKeyGatewayPublicURL:      "https://api.example/mcp",
		APIKeyGatewayAccessAudience: "gateway-aud",
		APIKeyGatewayServiceSubject: serviceSubject,
		APIKeyGatewayVerifier:       gatewayVerifier,
		Runner:                      &mcp.RunnerClient{BaseURL: runner.URL},
	}))
	t.Cleanup(srv.Close)

	serviceTok := signAccess(t, key, "k1", map[string]any{
		"iss": "https://issuer.example", "aud": "gateway-aud", "type": "app",
		"sub": "", "common_name": "worker-service-client-id", "exp": now.Unix() + 60,
	})
	humanTok := signAccess(t, key, "k1", map[string]any{
		"iss": "https://issuer.example", "aud": "gateway-aud", "type": "app",
		"sub": "human-subject", "exp": now.Unix() + 60, "nbf": now.Unix() - 1,
	})
	mainTok := signAccess(t, key, "k1", map[string]any{
		"iss": "https://issuer.example", "aud": "main-aud", "type": "app",
		"sub": "human-subject", "exp": now.Unix() + 60, "nbf": now.Unix() - 1,
	})
	serviceOnMain := signAccess(t, key, "k1", map[string]any{
		"iss": "https://issuer.example", "aud": "main-aud", "type": "app",
		"sub": "", "common_name": "worker-service-client-id", "exp": now.Unix() + 60,
	})

	post := func(path, assertion, bearer string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"workspace_list","arguments":{}}}`))
		req.Header.Set("Content-Type", "application/json")
		if assertion != "" {
			req.Header.Set("Cf-Access-Jwt-Assertion", assertion)
		}
		if bearer != "" {
			req.Header.Set("Authorization", bearer)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	ok := post("/mcp-api-key", serviceTok, "Bearer "+apiKey)
	defer ok.Body.Close()
	if ok.StatusCode != 200 {
		t.Fatalf("ok status %d", ok.StatusCode)
	}
	if captured.OwnerID != "https://issuer.example\x00human-subject" {
		t.Fatalf("owner %q", captured.OwnerID)
	}
	if strings.Contains(string(captured.Principal), apiKey) || sawSecret {
		t.Fatal("api key leaked onto tools/call")
	}

	human := post("/mcp-api-key", humanTok, "Bearer "+apiKey)
	defer human.Body.Close()
	if human.StatusCode != http.StatusUnauthorized {
		t.Fatalf("human %d", human.StatusCode)
	}

	mainAud := post("/mcp-api-key", mainTok, "Bearer "+apiKey)
	defer mainAud.Body.Close()
	if mainAud.StatusCode != http.StatusUnauthorized {
		t.Fatalf("main aud %d", mainAud.StatusCode)
	}

	missingKey := post("/mcp-api-key", serviceTok, "")
	defer missingKey.Body.Close()
	if missingKey.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing key %d", missingKey.StatusCode)
	}

	onMCP := post("/mcp", mainTok, "Bearer "+apiKey)
	defer onMCP.Body.Close()
	if onMCP.StatusCode != http.StatusUnauthorized {
		t.Fatalf("key on /mcp %d", onMCP.StatusCode)
	}

	serviceMCP := post("/mcp", serviceOnMain, "")
	defer serviceMCP.Body.Close()
	if serviceMCP.StatusCode != http.StatusUnauthorized {
		t.Fatalf("service on /mcp %d", serviceMCP.StatusCode)
	}

	disabled := httptest.NewServer(Handler(Options{
		Mode:           auth.ModeCloudflareAccess,
		AccessVerifier: mainVerifier,
		Runner:         &mcp.RunnerClient{BaseURL: runner.URL},
	}))
	t.Cleanup(disabled.Close)
	req, _ := http.NewRequest(http.MethodPost, disabled.URL+"/mcp-api-key", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled lane %d", res.StatusCode)
	}
}

func TestProductionOptionsAPIKeyGatewayRequiresAccessMode(t *testing.T) {
	_, err := ProductionOptions(func(name string) string {
		switch name {
		case "MCP_BEARER_TOKEN":
			return "owner-secret-that-is-long-enough"
		case "API_KEY_AUTH_ENABLED":
			return "true"
		case "API_KEY_GATEWAY_PUBLIC_URL":
			return "https://api.example/mcp"
		default:
			return ""
		}
	})
	if err == nil {
		t.Fatal("API key gateway must require cloudflare-access")
	}
}
