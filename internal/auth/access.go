package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const serviceSubjectPrefix = "cf-service:"

// Failure is a Cloudflare Access assertion rejection reason.
type Failure string

const (
	FailMissingAssertion    Failure = "missing_assertion"
	FailMalformedAssertion  Failure = "malformed_assertion"
	FailUnsupportedAlg      Failure = "unsupported_algorithm"
	FailInvalidSignature    Failure = "invalid_signature"
	FailUnknownKey          Failure = "unknown_key"
	FailJWKSUnavailable     Failure = "jwks_unavailable"
	FailWrongIssuer         Failure = "wrong_issuer"
	FailWrongAudience       Failure = "wrong_audience"
	FailWrongTokenType      Failure = "wrong_token_type"
	FailInvalidSubject      Failure = "invalid_subject"
	FailInvalidLifetime     Failure = "invalid_lifetime"
	FailExpired             Failure = "expired_assertion"
	FailInactive            Failure = "inactive_assertion"
	FailIdentityNotAccepted Failure = "assertion_identity_not_accepted"
)

// Error is a verification failure. Reason is loggable; the JWT is not.
type Error struct{ Reason Failure }

func (e Error) Error() string { return "Cloudflare Access assertion verification failed" }

// Identity is a verified Access principal. The raw JWT is never stored.
type Identity struct {
	Principal Principal
	ExpiresAt int64
	Email     string
	Name      string
}

// AccessConfig is the Cloudflare Access trust material.
type AccessConfig struct {
	Issuer   string
	Audience string
	JWKSURL  string
}

type cachedKey struct {
	key        *rsa.PublicKey
	freshUntil time.Time
	staleUntil time.Time
}

// AccessVerifier verifies RS256 Access JWTs against a JWKS document.
type AccessVerifier struct {
	cfg     AccessConfig
	now     func() time.Time
	client  *http.Client
	mu      sync.Mutex
	keys    map[string]cachedKey
	missing map[string]time.Time
}

// NewAccessVerifier constructs a verifier. JWKS is fetched on first verify.
func NewAccessVerifier(cfg AccessConfig, client *http.Client, now func() time.Time) *AccessVerifier {
	if now == nil {
		now = time.Now
	}
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	return &AccessVerifier{cfg: cfg, now: now, client: client, keys: map[string]cachedKey{}, missing: map[string]time.Time{}}
}

// Verify checks iss/aud/type/exp and the RS256 signature. It never logs assertion.
func (v *AccessVerifier) Verify(assertion string) (Identity, error) {
	if assertion == "" {
		return Identity{}, Error{FailMissingAssertion}
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Identity{}, Error{FailMalformedAssertion}
	}
	headerJSON, err := b64decode(parts[0])
	if err != nil {
		return Identity{}, Error{FailMalformedAssertion}
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Identity{}, Error{FailMalformedAssertion}
	}
	if header.Alg != "RS256" {
		return Identity{}, Error{FailUnsupportedAlg}
	}
	if header.Kid == "" || len(header.Kid) > 200 {
		return Identity{}, Error{FailMalformedAssertion}
	}
	key, err := v.keyFor(header.Kid)
	if err != nil {
		return Identity{}, err
	}
	sig, err := b64decode(parts[2])
	if err != nil {
		return Identity{}, Error{FailMalformedAssertion}
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return Identity{}, Error{FailInvalidSignature}
	}
	payloadJSON, err := b64decode(parts[1])
	if err != nil {
		return Identity{}, Error{FailMalformedAssertion}
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return Identity{}, Error{FailMalformedAssertion}
	}
	now := v.now().Unix()
	if payload["iss"] != v.cfg.Issuer {
		return Identity{}, Error{FailWrongIssuer}
	}
	if !audienceOK(payload["aud"], v.cfg.Audience) {
		return Identity{}, Error{FailWrongAudience}
	}
	if payload["type"] != "app" {
		return Identity{}, Error{FailWrongTokenType}
	}
	rawSub, _ := payload["sub"].(string)
	common, _ := payload["common_name"].(string)
	subject, err := normalizeSubject(rawSub, common)
	if err != nil {
		return Identity{}, err
	}
	exp, ok := asInt(payload["exp"])
	if !ok {
		return Identity{}, Error{FailInvalidLifetime}
	}
	if now >= exp {
		return Identity{}, Error{FailExpired}
	}
	if nbf, present := payload["nbf"]; present {
		n, ok := asInt(nbf)
		if !ok {
			return Identity{}, Error{FailInvalidLifetime}
		}
		if now < n {
			return Identity{}, Error{FailInactive}
		}
	} else if rawSub != "" {
		return Identity{}, Error{FailInvalidLifetime}
	}
	id := Identity{Principal: Principal{Issuer: v.cfg.Issuer, Subject: subject}, ExpiresAt: exp}
	if email, _ := payload["email"].(string); email != "" {
		id.Email = email
	}
	if name, _ := payload["name"].(string); name != "" {
		id.Name = name
	}
	return id, nil
}

func (v *AccessVerifier) keyFor(kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	if cached, ok := v.keys[kid]; ok && v.now().Before(cached.freshUntil) {
		key := cached.key
		v.mu.Unlock()
		return key, nil
	}
	if until, ok := v.missing[kid]; ok && v.now().Before(until) {
		v.mu.Unlock()
		return nil, Error{FailUnknownKey}
	}
	v.mu.Unlock()
	if err := v.refresh(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if cached, ok := v.keys[kid]; ok {
		return cached.key, nil
	}
	v.missing[kid] = v.now().Add(30 * time.Second)
	return nil, Error{FailUnknownKey}
}

func (v *AccessVerifier) refresh() error {
	req, err := http.NewRequest(http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return Error{FailJWKSUnavailable}
	}
	req.Header.Set("Accept", "application/json")
	res, err := v.client.Do(req)
	if err != nil {
		return Error{FailJWKSUnavailable}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Error{FailJWKSUnavailable}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65_536))
	if err != nil {
		return Error{FailJWKSUnavailable}
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Keys) == 0 || len(doc.Keys) > 32 {
		return Error{FailJWKSUnavailable}
	}
	next := map[string]cachedKey{}
	now := v.now()
	for _, jwk := range doc.Keys {
		if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" || jwk["use"] != "sig" || jwk["kid"] == "" {
			return Error{FailJWKSUnavailable}
		}
		pub, err := rsaFromJWK(jwk["n"], jwk["e"])
		if err != nil {
			return Error{FailJWKSUnavailable}
		}
		next[jwk["kid"]] = cachedKey{key: pub, freshUntil: now.Add(5 * time.Minute), staleUntil: now.Add(15 * time.Minute)}
	}
	v.mu.Lock()
	v.keys = next
	v.mu.Unlock()
	return nil
}

func rsaFromJWK(n, e string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, err
	}
	exp := 0
	for _, b := range eb {
		exp = exp<<8 | int(b)
	}
	if exp == 0 {
		return nil, fmt.Errorf("exp")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: exp}, nil
}

func normalizeSubject(raw, common string) (string, error) {
	if raw == "" {
		if strings.TrimSpace(common) == "" || len(common) > 320 {
			return "", Error{FailInvalidSubject}
		}
		return serviceSubjectPrefix + base64.RawURLEncoding.EncodeToString([]byte(common)), nil
	}
	if strings.TrimSpace(raw) != raw || len(raw) > 512 || strings.HasPrefix(raw, serviceSubjectPrefix) {
		return "", Error{FailInvalidSubject}
	}
	return raw, nil
}

func audienceOK(value any, want string) bool {
	if s, ok := value.(string); ok {
		return s == want
	}
	if arr, ok := value.([]any); ok {
		for _, item := range arr {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int64:
		return n, true
	default:
		return 0, false
	}
}

func b64decode(s string) ([]byte, error) {
	if len(s) > 32_768 {
		return nil, fmt.Errorf("too long")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// ReasonOf extracts a Failure from err.
func ReasonOf(err error) Failure {
	if e, ok := err.(Error); ok {
		return e.Reason
	}
	return ""
}
