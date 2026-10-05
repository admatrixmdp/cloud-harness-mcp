package git

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// AppConfig is the GitHub App identity used to mint installation tokens.
type AppConfig struct {
	AppID          string
	InstallationID string
	PrivateKey     []byte
}

// MintedToken is a short-lived installation token. Never log Token.
type MintedToken struct {
	Token     string
	ExpiresAt time.Time
}

// Stdin writes the token for helper containers. Docker argv must not include it.
func (t MintedToken) Stdin() string { return t.Token }

// AppJWT is the RS256 assertion GitHub requires before minting.
func AppJWT(cfg AppConfig, now time.Time) (string, error) {
	if cfg.AppID == "" {
		return "", fmt.Errorf("%s: GitHub App is not configured", protocol.ErrorUnavailable)
	}
	key, err := parseRSAPrivateKey(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("%s: GitHub App private key is invalid", protocol.ErrorUnavailable)
	}
	if now.IsZero() {
		now = time.Now()
	}
	iat := now.Add(-60 * time.Second).Unix()
	exp := now.Add(9 * time.Minute).Unix()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iat": iat, "exp": exp, "iss": cfg.AppID})
	unsigned := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("%s: GitHub App JWT signing failed", protocol.ErrorUnavailable)
	}
	return unsigned + "." + b64(sig), nil
}

// MintRequest is the GitHub installation-token HTTP request. The JWT is in
// Authorization only; the private key never leaves this process.
func MintRequest(cfg AppConfig, repository string, now time.Time) (*http.Request, error) {
	jwt, err := AppJWT(cfg, now)
	if err != nil {
		return nil, err
	}
	if cfg.InstallationID == "" {
		return nil, fmt.Errorf("%s: GitHub App installation is not configured", protocol.ErrorUnavailable)
	}
	body := []byte(`{}`)
	if repository != "" {
		payload, err := json.Marshal(map[string]any{"repositories": []string{repository}})
		if err != nil {
			return nil, err
		}
		body = payload
	}
	url := "https://api.github.com/app/installations/" + urlPath(cfg.InstallationID) + "/access_tokens"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// ParseMintResponse reads a GitHub access-token payload without logging it.
func ParseMintResponse(raw []byte) (MintedToken, error) {
	var payload struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Token == "" {
		return MintedToken{}, fmt.Errorf("%s: GitHub App could not mint a repository-scoped installation token", protocol.ErrorUnavailable)
	}
	exp, _ := time.Parse(time.RFC3339, payload.ExpiresAt)
	return MintedToken{Token: payload.Token, ExpiresAt: exp}, nil
}

// MintInstallationToken posts the signed JWT. Tests inject HTTP.
func MintInstallationToken(cfg AppConfig, repository string, client *http.Client, now time.Time) (MintedToken, error) {
	req, err := MintRequest(cfg, repository, now)
	if err != nil {
		return MintedToken{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return MintedToken{}, fmt.Errorf("%s: GitHub App could not mint a repository-scoped installation token", protocol.ErrorUnavailable)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return MintedToken{}, fmt.Errorf("%s: GitHub App could not mint a repository-scoped installation token", protocol.ErrorUnavailable)
	}
	if res.StatusCode >= 300 {
		return MintedToken{}, fmt.Errorf("%s: GitHub App could not mint a repository-scoped installation token", protocol.ErrorUnavailable)
	}
	return ParseMintResponse(raw)
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("pem")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not rsa")
	}
	return key, nil
}

func b64(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func urlPath(id string) string {
	id = strings.TrimSpace(id)
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		return ""
	}
	return id
}

// RequestLeaksMaterial reports whether the mint request echoed the PEM or a ghs_ token.
func RequestLeaksMaterial(req *http.Request, pemBytes []byte, minted string) bool {
	if req == nil {
		return false
	}
	auth := req.Header.Get("Authorization")
	if bytes.Contains([]byte(auth), pemBytes) || strings.Contains(auth, "BEGIN") {
		return true
	}
	if minted != "" && strings.Contains(auth, minted) {
		return true
	}
	return false
}
