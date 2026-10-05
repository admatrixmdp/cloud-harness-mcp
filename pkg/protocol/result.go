package protocol

// ToolResult is the public MCP result envelope from packages/contracts.
// JSON field names must remain byte-compatible with ToolResultSchema.
type ToolResult struct {
	OK        bool           `json:"ok"`
	Message   string         `json:"message"`
	Data      any            `json:"data,omitempty"`
	Error     *ToolError     `json:"error,omitempty"`
	Truncated bool           `json:"truncated"`
	Cursor    string         `json:"cursor,omitempty"`
}

// ToolError is the structured error object inside ToolResult.
type ToolError struct {
	Code               ErrorCode `json:"code"`
	Message            string    `json:"message"`
	Retryable          bool      `json:"retryable"`
	RetryAfterMs       *int      `json:"retryAfterMs,omitempty"`
	Deadline           string    `json:"deadline,omitempty"`
	GrantRequest       any       `json:"grantRequest,omitempty"`
	Operation          string    `json:"operation,omitempty"`
	Repository         string    `json:"repository,omitempty"`
	RequiredCapability string    `json:"requiredCapability,omitempty"`
	CurrentRemoteOID   string    `json:"currentRemoteOid,omitempty"`
	ExpectedRemoteOID  string    `json:"expectedRemoteOid,omitempty"`
	CurrentHeadOID     string    `json:"currentHeadOid,omitempty"`
	ExpectedHeadOID    string    `json:"expectedHeadOid,omitempty"`
	ResumeAction       string    `json:"resumeAction,omitempty"`
}

// Success returns a non-truncated ok result.
func Success(message string, data any) ToolResult {
	return ToolResult{OK: true, Message: message, Data: data, Truncated: false}
}

// Fail returns a failed result with the given public error code.
func Fail(code ErrorCode, message string, retryable bool) ToolResult {
	return ToolResult{
		OK:      false,
		Message: message,
		Error: &ToolError{
			Code:      code,
			Message:   message,
			Retryable: retryable,
		},
		Truncated: false,
	}
}
