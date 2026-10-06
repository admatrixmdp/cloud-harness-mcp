package typesafe

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Bounds and questions are the reviewable TypeSafe controls (today
// apps/runner/src/typesafe-questions.ts). A prompt never leaves the control
// plane unless these pass.
const (
	DefaultModel    = "jev-latest"
	DefaultEndpoint = "https://api.typesafe.ai/v1/systemone"
	AllowedHost     = "api.typesafe.ai"

	GateThreshold = 0.6
	FitsThreshold = 0.6
	Shortlist     = 3

	MaxEgressBytes   = 4096
	MaxEgressCeiling = 8192
	MinPromptChars   = 24

	IndexDescriptionMax = 60
	DescriptionFullMax  = 400
	BodyExcerptMax      = 700
	RosterFileMaxBytes  = 262144

	CallTimeoutMS = 1500
	TotalBudgetMS = 2500

	CacheTTLMS         = 15 * 60_000
	CacheMaxEntries    = 500
	RateLimitPerMinute = 60
)

// GateQuestion is one of the three first-call noul questions.
type GateQuestion struct {
	Key      string
	Text     string
	Inverted bool
}

// GateQuestions is the ordered first-call gate. Agreement with an inverted
// question lowers the gate.
var GateQuestions = []GateQuestion{
	{Key: "acts_on_user_system", Text: "Does this request have to act on the user's system to be satisfied, rather than produce text?", Inverted: false},
	{Key: "would_follow_documented_procedure", Text: "Would a documented, repeatable procedure answer this request better than free prose?", Inverted: false},
	{Key: "prose_suffices", Text: "Is ordinary prose sufficient to answer this request?", Inverted: true},
}

var slashCommand = regexp.MustCompile(`^/\S+$`)

// GateValue averages the three noul answers. A missing answer is skipped rather
// than treated as a pass; unanswered questions shrink the denominator only when
// present, matching today apps/runner typesafe-questions gateValue.
func GateValue(answers map[string]float64) float64 {
	var total float64
	for _, q := range GateQuestions {
		answer, ok := answers[q.Key]
		if !ok {
			continue
		}
		bounded := answer
		if bounded < 0 {
			bounded = 0
		}
		if bounded > 1 {
			bounded = 1
		}
		if q.Inverted {
			bounded = 1 - bounded
		}
		total += bounded
	}
	return total / float64(len(GateQuestions))
}

// ShortCircuitReason is a local decision: no outbound call is made.
func ShortCircuitReason(enabled bool, rosterSize int, prompt string) string {
	if !enabled {
		return "disabled"
	}
	if rosterSize <= 0 {
		return "empty_roster"
	}
	trimmed := strings.TrimSpace(prompt)
	if slashCommand.MatchString(trimmed) {
		return "slash_command"
	}
	if utf8.RuneCountInString(trimmed) < MinPromptChars {
		return "prompt_too_short"
	}
	return ""
}
