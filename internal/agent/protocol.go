package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	MaxProtocolRecordBytes = 8 * 1024 * 1024
	MaxProtocolQueueBytes  = 16 * 1024 * 1024
)

// StartRecord is the first stdin JSONL line the agent runtime receives.
// Prompt and lease live only on this wire, never in MCP results or logs.
type StartRecord struct {
	Type      string       `json:"type"`
	RequestID string       `json:"requestId"`
	AgentID   string       `json:"agentId"`
	Prompt    string       `json:"prompt"`
	Tools     []string     `json:"tools"`
	Gateway   StartGateway `json:"gateway"`
	Model     StartModel   `json:"model"`
	Limits    StartLimits  `json:"limits"`
}

// StartGateway binds the opaque lease to a profile. The lease is never logged.
type StartGateway struct {
	Profile string `json:"profile"`
	Lease   string `json:"lease"`
}

// StartModel is the public model metadata the runtime needs.
type StartModel struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	API           string    `json:"api"`
	Reasoning     bool      `json:"reasoning"`
	ContextWindow int       `json:"contextWindow"`
	MaxTokens     int       `json:"maxTokens"`
	Cost          ModelCost `json:"cost"`
}

// ModelCost is dollars-per-token pricing copied from the profile.
type ModelCost struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cacheRead"`
	CacheWrite float64 `json:"cacheWrite"`
}

// StartLimits bound the runtime's event/output budget.
type StartLimits struct {
	DeadlineMs         int `json:"deadlineMs"`
	MaxEvents          int `json:"maxEvents"`
	MaxOutputBytes     int `json:"maxOutputBytes"`
	MaxEventBytes      int `json:"maxEventBytes"`
	MaxToolResultBytes int `json:"maxToolResultBytes"`
}

// MessageRecord is a steer/follow-up line on stdin.
type MessageRecord struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	Behavior  string `json:"behavior"`
	Text      string `json:"text"`
}

// CancelRecord asks the runtime to stop.
type CancelRecord struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	Reason    string `json:"reason,omitempty"`
}

// ToolResultRecord returns a proxied tool outcome.
type ToolResultRecord struct {
	Type      string           `json:"type"`
	RequestID string           `json:"requestId"`
	Final     bool             `json:"final"`
	IsError   bool             `json:"isError"`
	Content   []ToolResultText `json:"content"`
}

// ToolResultText is one text content part.
type ToolResultText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// OutputRecord is one stdout JSONL line from the runtime.
type OutputRecord struct {
	Type       string          `json:"type"`
	Sequence   int             `json:"sequence,omitempty"`
	Event      json.RawMessage `json:"event,omitempty"`
	RequestID  string          `json:"requestId,omitempty"`
	ToolCallID string          `json:"toolCallId,omitempty"`
	Operation  string          `json:"operation,omitempty"`
	Input      json.RawMessage `json:"input,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Usage      *Usage          `json:"usage,omitempty"`
	State      string          `json:"state,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// Usage is the runtime's token/cost snapshot.
type Usage struct {
	Input      int     `json:"input"`
	Output     int     `json:"output"`
	CacheRead  int     `json:"cacheRead"`
	CacheWrite int     `json:"cacheWrite"`
	Total      int     `json:"total"`
	Cost       float64 `json:"cost"`
}

var terminalStates = map[string]struct{}{
	"SUCCEEDED": {}, "FAILED": {}, "CANCELLED": {}, "TIMED_OUT": {}, "LIMIT_EXCEEDED": {}, "INTERRUPTED": {},
}

// EncodeRecord writes one LF-terminated JSON object. Oversized records fail closed.
func EncodeRecord(w io.Writer, rec any) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(raw)+1 > MaxProtocolRecordBytes {
		return fmt.Errorf("agent protocol input exceeds the record limit")
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

// DecodeOutput parses one JSONL output record.
func DecodeOutput(line []byte) (OutputRecord, error) {
	if len(line) == 0 || len(line) > MaxProtocolRecordBytes {
		return OutputRecord{}, fmt.Errorf("agent protocol record is invalid")
	}
	var rec OutputRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return OutputRecord{}, fmt.Errorf("agent protocol record is invalid")
	}
	switch rec.Type {
	case "event":
		if rec.Sequence < 1 {
			return OutputRecord{}, fmt.Errorf("agent protocol record is invalid")
		}
	case "tool_request":
		if rec.RequestID == "" || rec.Operation == "" {
			return OutputRecord{}, fmt.Errorf("agent protocol record is invalid")
		}
	case "tool_cancel":
		if rec.RequestID == "" {
			return OutputRecord{}, fmt.Errorf("agent protocol record is invalid")
		}
	case "usage":
		if rec.Usage == nil || rec.Sequence < 1 {
			return OutputRecord{}, fmt.Errorf("agent protocol record is invalid")
		}
	case "terminal":
		if _, ok := terminalStates[rec.State]; !ok {
			return OutputRecord{}, fmt.Errorf("agent protocol record is invalid")
		}
	default:
		return OutputRecord{}, fmt.Errorf("agent protocol record is invalid")
	}
	return rec, nil
}

// Channel is a JSONL stdin/stdout session with one agent runtime.
type Channel struct {
	mu     sync.Mutex
	closed bool
	in     io.WriteCloser
	out    *bufio.Reader
	queued int
}

// NewChannel wraps the docker run pipes. Prompt/lease only travel as JSONL.
func NewChannel(stdin io.WriteCloser, stdout io.Reader) *Channel {
	return &Channel{in: stdin, out: bufio.NewReaderSize(stdout, 64*1024)}
}

// Send writes one input record. Closed channels fail with CONFLICT semantics.
func (c *Channel) Send(rec any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("agent protocol channel is closed")
	}
	return EncodeRecord(c.in, rec)
}

// Recv reads the next output record. Partial EOF is an error.
func (c *Channel) Recv() (OutputRecord, error) {
	for {
		line, err := c.out.ReadBytes('\n')
		if err != nil {
			if err == io.EOF && len(line) == 0 {
				return OutputRecord{}, io.EOF
			}
			if err == io.EOF {
				return OutputRecord{}, fmt.Errorf("agent protocol ended with a partial record")
			}
			return OutputRecord{}, err
		}
		c.queued += len(line)
		if c.queued > MaxProtocolQueueBytes {
			return OutputRecord{}, fmt.Errorf("agent protocol receive queue exceeded its bound")
		}
		line = trimNL(line)
		if len(line) == 0 {
			continue
		}
		return DecodeOutput(line)
	}
}

// CloseInput closes stdin so the runtime can exit.
func (c *Channel) CloseInput() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	_ = c.in.Close()
}

func trimNL(line []byte) []byte {
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line
}

// RedactProtocolJSON strips prompt and lease from a protocol payload for logs.
func RedactProtocolJSON(raw string) string {
	out := raw
	if i := strings.Index(out, `"prompt"`); i >= 0 {
		out = out[:i] + `"prompt":"[redacted]"` + skipJSONString(out[i+len(`"prompt"`):])
	}
	if i := strings.Index(out, `"lease"`); i >= 0 {
		out = out[:i] + `"lease":"[redacted]"` + skipJSONString(out[i+len(`"lease"`):])
	}
	return out
}

func skipJSONString(rest string) string {
	rest = strings.TrimLeft(rest, " :")
	if !strings.HasPrefix(rest, `"`) {
		return rest
	}
	i := 1
	for i < len(rest) {
		r, size := utf8.DecodeRuneInString(rest[i:])
		if r == '\\' {
			i += size
			if i < len(rest) {
				_, n := utf8.DecodeRuneInString(rest[i:])
				i += n
			}
			continue
		}
		if r == '"' {
			return rest[i+size:]
		}
		i += size
	}
	return ""
}
