package typesafe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RosterEntry is one skill the engine may name. The name is the only value
// that can ever reach the caller as a suggestion.
type RosterEntry struct {
	Name             string
	Source           string
	ContentSHA256    string
	IndexDescription string
	DescriptionFull  string
	BodyExcerpt      string
}

// Outcome is the public skill_suggest data envelope. Prompt text never appears.
type Outcome struct {
	Suggested      *Suggestion `json:"suggested"`
	Reason         string      `json:"reason,omitempty"`
	Cached         bool        `json:"cached"`
	LatencyMs      int         `json:"latencyMs"`
	OutboundCalls  int         `json:"outboundCalls"`
	RedactionCount int         `json:"redactionCount"`
	InputTokens    int         `json:"inputTokens,omitempty"`
	OutputTokens   int         `json:"outputTokens,omitempty"`
	Truncated      bool        `json:"truncated,omitempty"`
}

// Suggestion is a roster name plus gate/fit scalars. Never model prose.
type Suggestion struct {
	Name       string  `json:"name"`
	Gate       float64 `json:"gate"`
	Fit        float64 `json:"fit"`
	Confidence float64 `json:"confidence"`
}

// Config wires the TypeSafe HTTPS path. An empty APIKey means not_configured
// with zero outbound calls.
type Config struct {
	APIKey         func() string
	Secrets        func() map[string]string
	Enabled        func() bool
	Endpoint       string
	Model          string
	MaxEgressBytes int
	HTTP           *http.Client
	RoundTrip      func(*http.Request) (*http.Response, error)
	Now            func() time.Time
}

// Suggester posts a redacted prompt to TypeSafe. Upstream failure degrades to
// no suggestion; redaction failure sends nothing.
type Suggester struct {
	cfg    Config
	mu     sync.Mutex
	cache  map[string]cacheEntry
	order  []string
	stamps []time.Time
}

type cacheEntry struct {
	expires time.Time
	outcome Outcome
}

// New returns a suggester. Tests inject HTTP and Now.
func New(cfg Config) *Suggester {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: time.Duration(CallTimeoutMS) * time.Millisecond}
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEndpoint
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	return &Suggester{cfg: cfg, cache: map[string]cacheEntry{}}
}

type ParsedAnswer struct {
	Choice string
	Nouls  map[string]float64
	Usage  struct {
		InputTokens  int
		OutputTokens int
	}
}

type Question struct {
	Type     string            `json:"type"`
	Question string            `json:"question"`
	Criteria map[string]string `json:"criteria"`
}

type Request struct {
	Model     string              `json:"model"`
	State     string              `json:"state"`
	Questions map[string]Question `json:"questions"`
}

type postResult struct {
	kind   string
	status int
	json   any
}

// ParseAnswer reads the live TypeSafe envelope. An unexpected shape is
// reported rather than guessed at.
func ParseAnswer(raw any) (ParsedAnswer, bool) {
	root, ok := raw.(map[string]any)
	if !ok {
		return ParsedAnswer{}, false
	}
	answers, ok := root["answers"].(map[string]any)
	if !ok {
		return ParsedAnswer{}, false
	}
	parsed := ParsedAnswer{Nouls: map[string]float64{}}
	for name, value := range answers {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		switch item["type"] {
		case "choice":
			if choice, ok := item["choice"].(string); ok {
				parsed.Choice = choice
			}
		case "noul":
			if noul, ok := asFloat(item["noul"]); ok {
				parsed.Nouls[name] = noul
			}
		}
	}
	if usage, ok := root["usage"].(map[string]any); ok {
		if n, ok := asFloat(usage["input_tokens"]); ok {
			parsed.Usage.InputTokens = int(n)
		}
		if n, ok := asFloat(usage["output_tokens"]); ok {
			parsed.Usage.OutputTokens = int(n)
		}
	}
	return parsed, true
}

// Suggest ranks the roster. Failures never throw and never echo the prompt.
func (s *Suggester) Suggest(ctx context.Context, ownerID, workspaceID, prompt, rosterDigest string, roster []RosterEntry) Outcome {
	started := s.cfg.Now()
	base := Outcome{Suggested: nil, Cached: false, LatencyMs: 0, OutboundCalls: 0, RedactionCount: 0}
	enabled := true
	if s.cfg.Enabled != nil {
		enabled = s.cfg.Enabled()
	}
	if reason := ShortCircuitReason(enabled, len(roster), prompt); reason != "" {
		base.Reason = reason
		base.LatencyMs = elapsed(started, s.cfg.Now())
		return base
	}
	if s.cfg.APIKey == nil || strings.TrimSpace(s.cfg.APIKey()) == "" {
		base.Reason = "not_configured"
		base.LatencyMs = elapsed(started, s.cfg.Now())
		return base
	}
	if s.endpoint() == "" {
		base.Reason = "invalid_endpoint"
		base.LatencyMs = elapsed(started, s.cfg.Now())
		return base
	}
	secrets, secretsOK := loadSecrets(s.cfg.Secrets)
	if !secretsOK {
		base.Reason = "redaction_failed"
		base.LatencyMs = elapsed(started, s.cfg.Now())
		return base
	}
	redaction, ok := RedactPrompt(prompt, secrets, s.cfg.MaxEgressBytes)
	if !ok {
		base.Reason = "redaction_failed"
		base.LatencyMs = elapsed(started, s.cfg.Now())
		return base
	}
	key := cacheKey(ownerID, workspaceID, rosterDigest, redaction.Text)
	if hit, ok := s.readCache(key); ok {
		hit.Cached = true
		hit.LatencyMs = elapsed(started, s.cfg.Now())
		hit.RedactionCount = redaction.Count
		return hit
	}
	if !s.permitCall() {
		base.Reason = "rate_limited"
		base.LatencyMs = elapsed(started, s.cfg.Now())
		return base
	}
	deadline := started.Add(time.Duration(TotalBudgetMS) * time.Millisecond)
	spent := func(partial Outcome) Outcome {
		partial.RedactionCount = redaction.Count
		partial.Truncated = redaction.Truncated
		partial.LatencyMs = elapsed(started, s.cfg.Now())
		if partial.Suggested == nil && partial.Reason == "" {
			partial.Reason = "connection_error"
		}
		return partial
	}
	var first ParsedAnswer
	outbound := 0
	inputTokens := 0
	outputTokens := 0
	for attempt := 0; attempt < 2; attempt++ {
		if s.cfg.Now().After(deadline) || s.cfg.Now().Equal(deadline) {
			return spent(Outcome{Reason: "budget_exceeded", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
		}
		outbound++
		settled := s.post(ctx, s.rankBody(roster, redaction.Text), deadline)
		if settled.kind == "timeout" {
			return spent(Outcome{Reason: "timeout", OutboundCalls: outbound})
		}
		if settled.kind == "threw" {
			return spent(Outcome{Reason: "connection_error", OutboundCalls: outbound})
		}
		if settled.kind == "http-error" {
			if settled.status == 401 {
				return spent(Outcome{Reason: "unauthorized", OutboundCalls: outbound})
			}
			if settled.status == 422 {
				return spent(Outcome{Reason: "unprocessable", OutboundCalls: outbound})
			}
			if (settled.status == 429 || settled.status == 529) && attempt == 0 {
				continue
			}
			if settled.status == 429 {
				return spent(Outcome{Reason: "rate_limited", OutboundCalls: outbound})
			}
			if settled.status == 529 {
				return spent(Outcome{Reason: "upstream_unavailable", OutboundCalls: outbound})
			}
			return spent(Outcome{Reason: "connection_error", OutboundCalls: outbound})
		}
		parsed, ok := ParseAnswer(settled.json)
		if !ok {
			return spent(Outcome{Reason: "unexpected_response", OutboundCalls: outbound})
		}
		first = parsed
		inputTokens += parsed.Usage.InputTokens
		outputTokens += parsed.Usage.OutputTokens
		break
	}
	if first.Nouls == nil {
		return spent(Outcome{Reason: "budget_exceeded", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
	}
	gate := GateValue(first.Nouls)
	if gate < GateThreshold {
		out := spent(Outcome{Reason: "below_gate", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
		s.writeCache(key, out)
		return out
	}
	n := Shortlist
	if n > len(roster) {
		n = len(roster)
	}
	shortlist := append([]RosterEntry{}, roster[:n]...)
	if first.Choice != "" && !rosterContains(roster, first.Choice) {
		return spent(Outcome{Reason: "invalid_choice", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
	}
	ranked := shortlist
	if first.Choice != "" {
		ranked = reorder(shortlist, first.Choice)
	}
	if s.cfg.Now().After(deadline) || s.cfg.Now().Equal(deadline) {
		return spent(Outcome{Reason: "budget_exceeded", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
	}
	outbound++
	settled := s.post(ctx, s.rerankBody(ranked, redaction.Text), deadline)
	if settled.kind != "ok" {
		return spent(Outcome{Reason: "upstream_unavailable", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
	}
	second, ok := ParseAnswer(settled.json)
	if !ok {
		return spent(Outcome{Reason: "unexpected_response", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
	}
	inputTokens += second.Usage.InputTokens
	outputTokens += second.Usage.OutputTokens
	bestName := ""
	bestFit := -1.0
	for _, entry := range ranked {
		fit := second.Nouls["fits::"+entry.Name]
		if fit > bestFit {
			bestFit = fit
			bestName = entry.Name
		}
	}
	if bestFit < FitsThreshold {
		return spent(Outcome{Reason: "below_fit", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
	}
	if !rosterContains(roster, bestName) {
		return spent(Outcome{Reason: "invalid_choice", OutboundCalls: outbound, InputTokens: inputTokens, OutputTokens: outputTokens})
	}
	conf := gate * bestFit
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}
	out := Outcome{
		Suggested:      &Suggestion{Name: bestName, Gate: gate, Fit: bestFit, Confidence: conf},
		Cached:         false,
		OutboundCalls:  outbound,
		RedactionCount: redaction.Count,
		Truncated:      redaction.Truncated,
		LatencyMs:      elapsed(started, s.cfg.Now()),
		InputTokens:    inputTokens,
		OutputTokens:   outputTokens,
	}
	s.writeCache(key, out)
	return out
}

func (s *Suggester) endpoint() string {
	raw := s.cfg.Endpoint
	if raw == "" {
		raw = DefaultEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "https" {
		return ""
	}
	if u.Host != AllowedHost {
		return ""
	}
	return u.String()
}

func (s *Suggester) permitCall() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	kept := s.stamps[:0]
	for _, stamp := range s.stamps {
		if now.Sub(stamp) < time.Minute {
			kept = append(kept, stamp)
		}
	}
	s.stamps = kept
	if len(s.stamps) >= RateLimitPerMinute {
		return false
	}
	s.stamps = append(s.stamps, now)
	return true
}

func (s *Suggester) readCache(key string) (Outcome, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hit, ok := s.cache[key]
	if !ok || !hit.expires.After(s.cfg.Now()) {
		delete(s.cache, key)
		return Outcome{}, false
	}
	s.touch(key)
	out := hit.outcome
	out.Cached = true
	return out, true
}

func (s *Suggester) writeCache(key string, outcome Outcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := outcome
	stored.Cached = false
	s.cache[key] = cacheEntry{expires: s.cfg.Now().Add(time.Duration(CacheTTLMS) * time.Millisecond), outcome: stored}
	s.touch(key)
	for len(s.order) > CacheMaxEntries {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.cache, oldest)
	}
}

func (s *Suggester) touch(key string) {
	for i, existing := range s.order {
		if existing == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	s.order = append(s.order, key)
}

func (s *Suggester) post(ctx context.Context, body Request, deadline time.Time) postResult {
	endpoint := s.endpoint()
	apiKey := ""
	if s.cfg.APIKey != nil {
		apiKey = s.cfg.APIKey()
	}
	if endpoint == "" || apiKey == "" {
		return postResult{kind: "threw"}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return postResult{kind: "threw"}
	}
	remain := deadline.Sub(s.cfg.Now())
	if remain <= 0 {
		return postResult{kind: "timeout"}
	}
	timeout := time.Duration(CallTimeoutMS) * time.Millisecond
	if remain < timeout {
		timeout = remain
	}
	if timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return postResult{kind: "threw"}
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	var res *http.Response
	if s.cfg.RoundTrip != nil {
		res, err = s.cfg.RoundTrip(req)
	} else {
		res, err = s.cfg.HTTP.Do(req)
	}
	if err != nil {
		if reqCtx.Err() != nil || strings.Contains(strings.ToLower(err.Error()), "timeout") || strings.Contains(err.Error(), "context deadline") {
			return postResult{kind: "timeout"}
		}
		return postResult{kind: "threw"}
	}
	defer res.Body.Close()
	limited := io.LimitReader(res.Body, 1<<20)
	payload, _ := io.ReadAll(limited)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return postResult{kind: "http-error", status: res.StatusCode}
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return postResult{kind: "threw"}
	}
	return postResult{kind: "ok", json: decoded}
}

func (s *Suggester) rankBody(roster []RosterEntry, prompt string) Request {
	criteria := map[string]string{}
	for _, entry := range roster {
		criteria[entry.Name] = entry.IndexDescription
	}
	questions := map[string]Question{
		"skill": {Type: "choice", Question: "Which skill, if any, should be used for this request?", Criteria: criteria},
	}
	for _, q := range GateQuestions {
		questions[q.Key] = Question{Type: "noul", Question: q.Text, Criteria: map[string]string{"true": "yes", "false": "no"}}
	}
	return Request{Model: s.cfg.Model, State: prompt, Questions: questions}
}

func (s *Suggester) rerankBody(shortlist []RosterEntry, prompt string) Request {
	criteria := map[string]string{}
	questions := map[string]Question{}
	for _, entry := range shortlist {
		criteria[entry.Name] = entry.DescriptionFull + "\n" + entry.BodyExcerpt
		questions["fits::"+entry.Name] = Question{
			Type: "noul", Question: "Does the skill " + entry.Name + " fit this request?",
			Criteria: map[string]string{"true": "fits", "false": "does not fit"},
		}
	}
	questions["skill"] = Question{Type: "choice", Question: "Which of these skills fits the request best?", Criteria: criteria}
	return Request{Model: s.cfg.Model, State: prompt, Questions: questions}
}

func cacheKey(ownerID, workspaceID, digest, redacted string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{ownerID, workspaceID, digest, redacted}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func rosterContains(roster []RosterEntry, name string) bool {
	for _, entry := range roster {
		if entry.Name == name {
			return true
		}
	}
	return false
}

func reorder(shortlist []RosterEntry, choice string) []RosterEntry {
	out := make([]RosterEntry, 0, len(shortlist))
	for _, entry := range shortlist {
		if entry.Name == choice {
			out = append(out, entry)
		}
	}
	for _, entry := range shortlist {
		if entry.Name != choice {
			out = append(out, entry)
		}
	}
	return out
}

func elapsed(started, now time.Time) int {
	n := int(now.Sub(started).Milliseconds())
	if n < 0 {
		return 0
	}
	return n
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func loadSecrets(fn func() map[string]string) (map[string]string, bool) {
	if fn == nil {
		return nil, true
	}
	ok := true
	var out map[string]string
	func() {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		out = fn()
	}()
	return out, ok
}

// None is the empty suggestion envelope used by local/unconfigured paths.
func None(reason string) Outcome {
	return Outcome{Suggested: nil, Reason: reason, Cached: false, LatencyMs: 0, OutboundCalls: 0, RedactionCount: 0}
}

func (o Outcome) Data() map[string]any {
	out := map[string]any{
		"suggested":      nil,
		"cached":         o.Cached,
		"latencyMs":      o.LatencyMs,
		"outboundCalls":  o.OutboundCalls,
		"redactionCount": o.RedactionCount,
	}
	if o.Suggested != nil {
		out["suggested"] = map[string]any{
			"name": o.Suggested.Name, "gate": o.Suggested.Gate, "fit": o.Suggested.Fit, "confidence": o.Suggested.Confidence,
		}
	}
	if o.Reason != "" {
		out["reason"] = o.Reason
	}
	if o.InputTokens != 0 {
		out["inputTokens"] = o.InputTokens
	}
	if o.OutputTokens != 0 {
		out["outputTokens"] = o.OutputTokens
	}
	if o.Truncated {
		out["truncated"] = true
	}
	return out
}
