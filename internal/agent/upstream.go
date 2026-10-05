package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
)

const maxUpstreamBody = 1 << 20

var forbiddenBodyFields = []string{"api_key", "base_url", "upstream_url", "url", "headers"}

// Upstream is the trusted provider target for one profile. Credential never
// appears in logs, docker argv, or downstream responses.
type Upstream struct {
	URL              string
	Credential       string
	CredentialHeader string
	CredentialScheme string
	AllowPrivate     bool
	MaxRequestBytes  int
	Timeout          time.Duration
	Transport        http.RoundTripper
}

func (p Profile) hasUpstream() bool {
	return p.Upstream.URL != "" && p.Upstream.Credential != ""
}

func (u Upstream) maxBytes() int {
	if u.MaxRequestBytes > 0 {
		return u.MaxRequestBytes
	}
	return maxUpstreamBody
}

func (u Upstream) timeout() time.Duration {
	if u.Timeout > 0 {
		return u.Timeout
	}
	return 30 * time.Second
}

func (u Upstream) headerName() string {
	if u.CredentialHeader != "" {
		return u.CredentialHeader
	}
	return "Authorization"
}

func (u Upstream) credentialValue() string {
	if u.CredentialScheme == "" {
		return u.Credential
	}
	return u.CredentialScheme + " " + u.Credential
}

func sanitizeBody(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("request body is required")
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("request body must be valid UTF-8 JSON")
	}
	for _, key := range forbiddenBodyFields {
		if _, ok := obj[key]; ok {
			return nil, fmt.Errorf("request body contains a forbidden routing or credential field")
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func validateUpstreamURL(raw string, allowPrivate bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("upstream must be credential-free HTTPS")
	}
	host := strings.ToLower(parsed.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && git.AddressForbidden(host) {
			return nil, fmt.Errorf("unsafe upstream address")
		}
	}
	return parsed, nil
}

func proxyUpstream(w http.ResponseWriter, r *http.Request, profile Profile) {
	up := profile.Upstream
	target, err := validateUpstreamURL(up.URL, up.AllowPrivate)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "unsafe_upstream")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(up.maxBytes()+1)))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_body")
		return
	}
	if len(body) > up.maxBytes() {
		writeErr(w, http.StatusRequestEntityTooLarge, "request_body_too_large")
		return
	}
	body, err = sanitizeBody(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_body")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	req.Header.Set("User-Agent", "cloud-harness-model-gateway")
	req.Header.Set("Accept", "text/event-stream, application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(up.headerName(), up.credentialValue())
	if sid := r.Header.Get("x-agent-id"); sid != "" {
		req.Header.Set("x-opencode-session", sid)
	}
	client := &http.Client{Timeout: up.timeout(), Transport: up.Transport}
	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}
	res, err := client.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	if up.Credential != "" && bytes.Contains(raw, []byte(up.Credential)) {
		writeErr(w, http.StatusBadGateway, "provider_attempted_credential_disclosure")
		return
	}
	ct := res.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(raw)
}
