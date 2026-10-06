package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
)

// ProviderUsage is the settled token/cost snapshot from a provider response.
type ProviderUsage struct {
	InputTokens  int
	OutputTokens int
	CostMicros   int64
}

// Reservation is the pre-reserved budget for one upstream call.
type Reservation struct {
	InputTokens  int
	OutputTokens int
	CostMicros   int64
	Key          string
}

func costMicros(tokens int, pricePerMillion int64) int64 {
	if tokens <= 0 || pricePerMillion == 0 {
		return 0
	}
	numerator := int64(tokens) * pricePerMillion
	return (numerator + 999_999) / 1_000_000
}

func requestedOutputTokens(body map[string]any, profile Profile, path string) (int, error) {
	fields := []string{"max_tokens", "max_completion_tokens"}
	if path == "/v1/responses" || profile.DownstreamPath == "/v1/responses" {
		fields = []string{"max_output_tokens"}
	}
	requested := []int{}
	for _, field := range fields {
		v, ok := body[field]
		if !ok {
			continue
		}
		n, ok := asPositiveInt(v)
		if !ok {
			return 0, fmt.Errorf("%s must be a positive integer", field)
		}
		requested = append(requested, n)
	}
	delete(body, "max_completion_tokens")
	if len(requested) == 0 {
		if profile.Limits.MaxOutputTokens > 0 {
			return profile.Limits.MaxOutputTokens, nil
		}
		return 1, nil
	}
	min := requested[0]
	for _, n := range requested[1:] {
		if n < min {
			min = n
		}
	}
	return min, nil
}

func asPositiveInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n != math.Trunc(n) || n < 1 || n > float64(math.MaxInt32) {
			return 0, false
		}
		return int(n), true
	case int:
		if n < 1 {
			return 0, false
		}
		return n, true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 1 {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

func (g *Grant) reserve(body map[string]any, bodyBytes int, profile Profile, path string) (Reservation, error) {
	estimated := bodyBytes
	if estimated < 1 {
		estimated = 1
	}
	inputCap := g.RemainingInputTokens
	if profile.Limits.MaxInputTokens > 0 && profile.Limits.MaxInputTokens < inputCap {
		inputCap = profile.Limits.MaxInputTokens
	}
	if inputCap < 1 {
		return Reservation{}, fmt.Errorf("input token budget exceeded")
	}
	inputTokens := estimated
	if inputTokens > inputCap {
		return Reservation{}, fmt.Errorf("input token budget exceeded")
	}
	inputCost := costMicros(inputTokens, profile.InputMicrosPerMillion)
	if inputCost > g.RemainingCostMicros {
		return Reservation{}, fmt.Errorf("input cost budget exceeded")
	}
	requested, err := requestedOutputTokens(body, profile, path)
	if err != nil {
		return Reservation{}, err
	}
	outputCap := g.RemainingOutputTokens
	if profile.Limits.MaxOutputTokens > 0 && profile.Limits.MaxOutputTokens < outputCap {
		outputCap = profile.Limits.MaxOutputTokens
	}
	requested = minInt(requested, outputCap)
	affordable := requested
	if profile.OutputMicrosPerMillion != 0 {
		remain := g.RemainingCostMicros - inputCost
		if remain < 0 {
			remain = 0
		}
		affordable = int(remain * 1_000_000 / profile.OutputMicrosPerMillion)
		if affordable > requested {
			affordable = requested
		}
	}
	outputTokens := minInt(requested, affordable)
	if outputTokens < 1 {
		return Reservation{}, fmt.Errorf("output cost budget exhausted")
	}
	field := "max_tokens"
	if path == "/v1/responses" || profile.DownstreamPath == "/v1/responses" {
		field = "max_output_tokens"
	}
	body[field] = outputTokens
	if profile.Model != "" {
		body["model"] = profile.Model
	}
	body["stream"] = true
	if path == "/v1/chat/completions" || profile.DownstreamPath == "/v1/chat/completions" || profile.DownstreamPath == "" {
		body["stream_options"] = map[string]any{"include_usage": true}
	}
	res := Reservation{
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		CostMicros:   inputCost + costMicros(outputTokens, profile.OutputMicrosPerMillion),
	}
	g.RemainingInputTokens -= res.InputTokens
	g.RemainingOutputTokens -= res.OutputTokens
	g.RemainingCostMicros -= res.CostMicros
	return res, nil
}

func (g *Grant) reconcile(res Reservation, actual *ProviderUsage) ProviderUsage {
	usage := ProviderUsage{InputTokens: res.InputTokens, OutputTokens: res.OutputTokens, CostMicros: res.CostMicros}
	if actual != nil {
		usage.InputTokens = minInt(actual.InputTokens, res.InputTokens)
		usage.OutputTokens = minInt(actual.OutputTokens, res.OutputTokens)
		if actual.CostMicros < res.CostMicros {
			usage.CostMicros = actual.CostMicros
		}
	}
	g.RemainingInputTokens += res.InputTokens - usage.InputTokens
	g.RemainingOutputTokens += res.OutputTokens - usage.OutputTokens
	g.RemainingCostMicros += res.CostMicros - usage.CostMicros
	return usage
}

func usageFromProvider(raw []byte, profile Profile) *ProviderUsage {
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte("data:")) || bytes.Contains(trimmed, []byte("\ndata:")) {
		var last []byte
		for _, line := range bytes.Split(trimmed, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if bytes.Equal(payload, []byte("[DONE]")) {
				continue
			}
			last = payload
		}
		if len(last) == 0 {
			return nil
		}
		trimmed = last
	}
	var envelope struct {
		Usage *struct {
			InputTokens      *int `json:"input_tokens"`
			PromptTokens     *int `json:"prompt_tokens"`
			OutputTokens     *int `json:"output_tokens"`
			CompletionTokens *int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(trimmed, &envelope) != nil || envelope.Usage == nil {
		return nil
	}
	in, out := -1, -1
	if envelope.Usage.InputTokens != nil {
		in = *envelope.Usage.InputTokens
	} else if envelope.Usage.PromptTokens != nil {
		in = *envelope.Usage.PromptTokens
	}
	if envelope.Usage.OutputTokens != nil {
		out = *envelope.Usage.OutputTokens
	} else if envelope.Usage.CompletionTokens != nil {
		out = *envelope.Usage.CompletionTokens
	}
	if in < 0 || out < 0 {
		return nil
	}
	return &ProviderUsage{
		InputTokens:  in,
		OutputTokens: out,
		CostMicros:   costMicros(in, profile.InputMicrosPerMillion) + costMicros(out, profile.OutputMicrosPerMillion),
	}
}
