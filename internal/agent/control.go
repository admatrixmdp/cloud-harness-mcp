package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const maxControlRecordBytes = 1_048_576

// ControlRequest is one LF-terminated JSON record on the Unix control socket.
type ControlRequest struct {
	Operation       string `json:"operation"`
	LeaseID         string `json:"leaseId"`
	AgentID         string `json:"agentId"`
	ProfileID       string `json:"profileId"`
	TTLMs           int    `json:"ttlMs"`
	MaxInputTokens  int    `json:"maxInputTokens"`
	MaxOutputTokens int    `json:"maxOutputTokens"`
	MaxCostMicros   int64  `json:"maxCostMicros"`
	RequestID       string `json:"requestId"`
}

// ControlResponse is the one-line JSON reply. The issued lease never appears in logs.
type ControlResponse struct {
	OK      bool           `json:"ok"`
	Lease   string         `json:"lease,omitempty"`
	Revoked bool           `json:"revoked,omitempty"`
	Digest  *ControlDigest `json:"digest,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// ControlDigest is the status snapshot for the runner.
type ControlDigest struct {
	ActiveLeaseCount int `json:"activeLeaseCount"`
}

// ControlServer is the model-gateway Unix control plane. Mode 0600.
type ControlServer struct {
	Path     string
	Registry *Registry
	Profiles map[string]Profile
	mu       sync.Mutex
	ln       net.Listener
}

// ListenAndServe binds the Unix socket and serves one JSON record per connection.
func (s *ControlServer) ListenAndServe(ctx context.Context) error {
	if s.Path == "" {
		return fmt.Errorf("control socket path is required")
	}
	if s.Registry == nil {
		s.Registry = NewRegistry()
	}
	_ = os.Remove(s.Path)
	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.Path, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handle(conn)
	}
}

// Close unbinds the socket.
func (s *ControlServer) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	_ = os.Remove(s.Path)
	return nil
}

func (s *ControlServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	limited := io.LimitReader(conn, maxControlRecordBytes+1)
	raw, err := bufio.NewReader(limited).ReadBytes('\n')
	if err != nil {
		writeControl(conn, ControlResponse{Error: "control record unreadable"})
		return
	}
	if len(raw) > maxControlRecordBytes {
		writeControl(conn, ControlResponse{Error: "control record too large"})
		return
	}
	var req ControlRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeControl(conn, ControlResponse{Error: "invalid control record"})
		return
	}
	writeControl(conn, s.dispatch(req))
}

func (s *ControlServer) dispatch(req ControlRequest) ControlResponse {
	switch req.Operation {
	case "issue":
		profile, ok := s.Profiles[req.ProfileID]
		if !ok {
			return ControlResponse{Error: "unknown profile"}
		}
		token, err := s.Registry.Issue(IssueInput{
			LeaseID:         req.LeaseID,
			AgentID:         req.AgentID,
			ProfileID:       req.ProfileID,
			TTL:             time.Duration(req.TTLMs) * time.Millisecond,
			MaxInputTokens:  req.MaxInputTokens,
			MaxOutputTokens: req.MaxOutputTokens,
			MaxCostMicros:   req.MaxCostMicros,
		}, profile)
		if err != nil {
			return ControlResponse{Error: err.Error()}
		}
		return ControlResponse{OK: true, Lease: token}
	case "revoke":
		return ControlResponse{OK: true, Revoked: s.Registry.Revoke(req.LeaseID)}
	case "digest", "status", "ping":
		return ControlResponse{OK: true, Digest: &ControlDigest{ActiveLeaseCount: s.Registry.ActiveCount()}}
	default:
		return ControlResponse{Error: "unsupported control operation"}
	}
}

func writeControl(w io.Writer, resp ControlResponse) {
	if !resp.OK && resp.Error == "" {
		resp.Error = "control operation failed"
	}
	raw, _ := json.Marshal(resp)
	_, _ = w.Write(append(raw, '\n'))
}

// ControlClient posts one JSON record to a Unix control socket.
type ControlClient struct {
	Path    string
	Timeout time.Duration
}

// Issue mints a lease through the control plane. The token is never logged.
func (c *ControlClient) Issue(ctx context.Context, input IssueInput) (string, error) {
	ttlMs := int(input.TTL / time.Millisecond)
	resp, err := c.call(ctx, ControlRequest{
		Operation:       "issue",
		LeaseID:         input.LeaseID,
		AgentID:         input.AgentID,
		ProfileID:       input.ProfileID,
		TTLMs:           ttlMs,
		MaxInputTokens:  input.MaxInputTokens,
		MaxOutputTokens: input.MaxOutputTokens,
		MaxCostMicros:   input.MaxCostMicros,
	})
	if err != nil {
		return "", err
	}
	if !resp.OK || resp.Lease == "" {
		msg := resp.Error
		if msg == "" {
			msg = "model gateway omitted the issued lease"
		}
		return "", fmt.Errorf("%s", msg)
	}
	return resp.Lease, nil
}

// Revoke marks a lease unusable.
func (c *ControlClient) Revoke(ctx context.Context, leaseID string) error {
	_, err := c.call(ctx, ControlRequest{Operation: "revoke", LeaseID: leaseID})
	return err
}

func (c *ControlClient) call(ctx context.Context, req ControlRequest) (ControlResponse, error) {
	if c.Path == "" {
		return ControlResponse{}, fmt.Errorf("control socket path is required")
	}
	d := net.Dialer{Timeout: c.timeout()}
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return ControlResponse{}, fmt.Errorf("model gateway control request failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout()))
	raw, err := json.Marshal(req)
	if err != nil {
		return ControlResponse{}, err
	}
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		return ControlResponse{}, fmt.Errorf("model gateway control request failed")
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return ControlResponse{}, fmt.Errorf("model gateway returned an invalid control response")
	}
	var resp ControlResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return ControlResponse{}, fmt.Errorf("model gateway returned an invalid control response")
	}
	return resp, nil
}

func (c *ControlClient) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 10 * time.Second
}

// RedactControlJSON strips lease tokens from a control payload for logs.
func RedactControlJSON(raw string) string {
	if strings.Contains(raw, `"lease"`) {
		return `{"ok":true,"lease":"[redacted]"}`
	}
	return raw
}
