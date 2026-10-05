package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

func TestAccessVerifyHappyPathAndRejections(t *testing.T) {
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
	v := NewAccessVerifier(AccessConfig{Issuer: "https://issuer.example", Audience: "aud-1", JWKSURL: jwks.URL}, jwks.Client(), func() time.Time { return now })
	good := signAccess(t, key, "k1", map[string]any{
		"iss": "https://issuer.example", "aud": "aud-1", "type": "app",
		"sub": "user-1", "exp": now.Unix() + 60, "nbf": now.Unix() - 1, "email": "a@b.c",
	})
	id, err := v.Verify(good)
	if err != nil {
		t.Fatal(err)
	}
	if id.Principal.Subject != "user-1" || id.Email != "a@b.c" {
		t.Fatalf("%+v", id)
	}
	if _, err := v.Verify(""); ReasonOf(err) != FailMissingAssertion {
		t.Fatalf("missing: %v", err)
	}
	if _, err := v.Verify("a.b"); ReasonOf(err) != FailMalformedAssertion {
		t.Fatalf("malformed: %v", err)
	}
	wrongIss := signAccess(t, key, "k1", map[string]any{
		"iss": "other", "aud": "aud-1", "type": "app", "sub": "user-1", "exp": now.Unix() + 60, "nbf": now.Unix() - 1,
	})
	if _, err := v.Verify(wrongIss); ReasonOf(err) != FailWrongIssuer {
		t.Fatalf("iss: %v", err)
	}
	expired := signAccess(t, key, "k1", map[string]any{
		"iss": "https://issuer.example", "aud": "aud-1", "type": "app", "sub": "user-1", "exp": now.Unix() - 1, "nbf": now.Unix() - 10,
	})
	if _, err := v.Verify(expired); ReasonOf(err) != FailExpired {
		t.Fatalf("exp: %v", err)
	}
	badAlgHeader, _ := json.Marshal(map[string]string{"alg": "none", "kid": "k1"})
	payload := strings.Split(good, ".")[1]
	sig := strings.Split(good, ".")[2]
	noneTok := base64.RawURLEncoding.EncodeToString(badAlgHeader) + "." + payload + "." + sig
	if _, err := v.Verify(noneTok); ReasonOf(err) != FailUnsupportedAlg {
		t.Fatalf("alg: %v", err)
	}
}

func TestAccessVerifyDoesNotNeedAssertionInError(t *testing.T) {
	v := NewAccessVerifier(AccessConfig{Issuer: "iss", Audience: "aud", JWKSURL: "http://127.0.0.1:1/jwks"}, &http.Client{Timeout: time.Millisecond}, time.Now)
	token := "header.payload.signature-that-must-not-be-logged"
	_, err := v.Verify(token)
	if err == nil {
		t.Fatal("expected fail")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("assertion leaked in error")
	}
}
