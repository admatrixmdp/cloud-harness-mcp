package agent

import (
	"bufio"
	"bytes"
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
	Operation       string                        `json:"operation"`
	Type            string                        `json:"type,omitempty"`
	LeaseID         string                        `json:"leaseId"`
	AgentID         string                        `json:"agentId"`
	ProfileID       string                        `json:"profileId"`
	TTLMs           int                           `json:"ttlMs"`
	MaxInputTokens  int                           `json:"maxInputTokens"`
	MaxOutputTokens int                           `json:"maxOutputTokens"`
	MaxCostMicros   int64                         `json:"maxCostMicros"`
	RequestID       string                        `json:"requestId"`
	Sequence        int                           `json:"sequence"`
	Generation      int                           `json:"generation"`
	Credentials     map[string]SnapshotCredential `json:"credentials,omitempty"`
	Profiles        map[string]json.RawMessage    `json:"profiles,omitempty"`
}

// ControlResponse is the one-line JSON reply. The issued lease never appears in logs.
type ControlResponse struct {
	OK      bool           `json:"ok"`
	Lease   string         `json:"lease,omitempty"`
	Revoked bool           `json:"revoked,omitempty"`
	Ack     *ControlAck    `json:"ack,omitempty"`
	Digest  *ControlDigest `json:"digest,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// ControlAck is the apply_snapshot reply. Secrets never appear here.
type ControlAck struct {
	Type                  string `json:"type"`
	Sequence              int    `json:"sequence"`
	Generation            int    `json:"generation"`
	GatewayBootID         string `json:"gatewayBootId"`
	SnapshotDigest        string `json:"snapshotDigest"`
	ActiveProfileCount    int    `json:"activeProfileCount"`
	ActiveCredentialCount int    `json:"activeCredentialCount"`
}

// ControlDigest is the status snapshot for the runner.
type ControlDigest struct {
	GatewayBootID         string `json:"gatewayBootId"`
	SnapshotDigest        string `json:"snapshotDigest"`
	ActiveProfileCount    int    `json:"activeProfileCount"`
	ActiveCredentialCount int    `json:"activeCredentialCount"`
	ActiveLeaseCount      int    `json:"activeLeaseCount"`
}

// ControlServer is the model-gateway Unix control plane. Mode 0600.
type ControlServer struct {
	Path     string
	Registry *Registry
	Live     *LiveRegistry
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
	trimmed := bytes.TrimRight(raw, "\r\n")
	var req ControlRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		writeControl(conn, ControlResponse{Error: "invalid control record"})
		return
	}
	writeControl(conn, s.dispatch(req, trimmed))
}

func (s *ControlServer) lookupProfile(id string) (Profile, bool) {
	if s.Live != nil {
		if p, ok := s.Live.Profile(id); ok {
			return p, true
		}
	}
	p, ok := s.Profiles[id]
	return p, ok
}

func (s *ControlServer) dispatch(req ControlRequest, record []byte) ControlResponse {
	op := req.Operation
	if op == "" {
		op = req.Type
	}
	switch op {
	case "issue":
		profile, ok := s.lookupProfile(req.ProfileID)
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
	case "apply_snapshot":
		if s.Live == nil {
			return ControlResponse{Error: "dynamic gateway registry is unavailable"}
		}
		ack, err := s.Live.apply(Snapshot{
			Sequence:    req.Sequence,
			Generation:  req.Generation,
			Credentials: req.Credentials,
			Profiles:    req.Profiles,
		}, record)
		if err != nil {
			return ControlResponse{Error: err.Error()}
		}
		return ControlResponse{OK: true, Ack: &ack}
	case "digest", "status":
		leases := 0
		if s.Registry != nil {
			leases = s.Registry.ActiveCount()
		}
		d := ControlDigest{ActiveLeaseCount: leases}
		if s.Live != nil {
			d = s.Live.Digest(leases)
		}
		return ControlResponse{OK: true, Digest: &d}
	case "ping":
		return ControlResponse{OK: true}
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

// ApplySnapshot pushes decrypted credentials and revisions. Secrets never log.
func (c *ControlClient) ApplySnapshot(ctx context.Context, snap Snapshot) (ControlAck, error) {
	resp, err := c.call(ctx, ControlRequest{
		Operation:   "apply_snapshot",
		Sequence:    snap.Sequence,
		Generation:  snap.Generation,
		Credentials: snap.Credentials,
		Profiles:    snap.Profiles,
	})
	if err != nil {
		return ControlAck{}, err
	}
	if !resp.OK || resp.Ack == nil {
		msg := resp.Error
		if msg == "" {
			msg = "model gateway omitted snapshot ack"
		}
		return ControlAck{}, fmt.Errorf("%s", msg)
	}
	return *resp.Ack, nil
}

// QueryDigest reads the live gateway digest. Secrets never appear.
func (c *ControlClient) QueryDigest(ctx context.Context) (ControlDigest, error) {
	resp, err := c.call(ctx, ControlRequest{Operation: "digest"})
	if err != nil {
		return ControlDigest{}, err
	}
	if !resp.OK || resp.Digest == nil {
		msg := resp.Error
		if msg == "" {
			msg = "model gateway omitted status digest"
		}
		return ControlDigest{}, fmt.Errorf("%s", msg)
	}
	return *resp.Digest, nil
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
	if strings.Contains(raw, `"secret"`) {
		return `{"ok":true,"secret":"[redacted]"}`
	}
	return raw
}
