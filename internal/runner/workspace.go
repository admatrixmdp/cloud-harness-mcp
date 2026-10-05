package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/internal/store"
	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// Engine starts and stops workspace executors. Tests inject a fake.
type Engine interface {
	Create(ctx context.Context, rec store.Record) (containerName string, err error)
	Remove(ctx context.Context, containerName string) error
}

// noopEngine records create/remove without talking to Docker.
type noopEngine struct{}

func (noopEngine) Create(_ context.Context, rec store.Record) (string, error) {
	id := rec.ID
	if len(id) < 19 {
		id = id + strings.Repeat("x", 19-len(id))
	}
	return "cloud-harness-ws-" + strings.ToLower(id[3:19]), nil
}

func (noopEngine) Remove(context.Context, string) error { return nil }

// Config is the runner workspace policy.
type Config struct {
	AllowedGitHosts []string
	NetworkProfile  protocol.NetworkProfile
	IdleTTL         time.Duration
	WallTTL         time.Duration
	InstanceID      string
	Attestor        sandbox.Attestor
}

func (c Config) withDefaults() Config {
	if c.NetworkProfile == "" {
		c.NetworkProfile = sandbox.DefaultNetworkProfile
	}
	if c.IdleTTL == 0 {
		c.IdleTTL = 5 * time.Minute
	}
	if c.WallTTL == 0 {
		c.WallTTL = 15 * time.Minute
	}
	if c.InstanceID == "" {
		c.InstanceID = "local"
	}
	if len(c.AllowedGitHosts) == 0 {
		c.AllowedGitHosts = []string{"github.com"}
	}
	return c
}

// Service executes public runner operations.
type Service struct {
	cfg    Config
	store  store.Store
	engine Engine
}

// NewService constructs a workspace service. engine may be nil (noop).
func NewService(cfg Config, st store.Store, engine Engine) *Service {
	if st == nil {
		st = store.NewMemory()
	}
	if engine == nil {
		engine = noopEngine{}
	}
	return &Service{cfg: cfg.withDefaults(), store: st, engine: engine}
}

type openInput struct {
	RepositoryURL               string `json:"repositoryUrl"`
	Ref                         string `json:"ref"`
	IdempotencyKey              string `json:"idempotencyKey"`
	NetworkProfile              string `json:"networkProfile"`
	NetworkMode                 any    `json:"networkMode"`
	EnvironmentID               string `json:"environmentId"`
	ConfirmEnvironmentInjection *bool  `json:"confirmEnvironmentInjection"`
	FetchDepth                  *int   `json:"fetchDepth"`
	ShallowSince                string `json:"shallowSince"`
}

// Execute runs one public runner operation.
func (s *Service) Execute(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	if !req.Operation.Known() {
		return protocol.Fail(protocol.ErrorInvalidInput, "unknown operation", false)
	}
	switch req.Operation {
	case protocol.OpWorkspaceOpen:
		return s.open(ctx, req)
	case protocol.OpWorkspaceList:
		return s.list(req)
	case protocol.OpWorkspaceStatus:
		return s.status(req)
	case protocol.OpWorkspaceClose:
		return s.close(ctx, req)
	case protocol.OpWorkspaceCapabilities:
		return protocol.Success("workspace capabilities", map[string]any{
			"networkProfiles":       []string{string(protocol.NetworkNone), string(protocol.DependencyAccess)},
			"defaultNetworkProfile": string(s.cfg.NetworkProfile),
		})
	default:
		return protocol.Fail(protocol.ErrorUnavailable, "Go-port runner has not implemented "+string(req.Operation)+" yet", true)
	}
}

func (s *Service) open(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	var input openInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid workspace_open input", false)
		}
	}
	if input.NetworkMode != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "networkMode was replaced by networkProfile; choose 'network-none' or 'dependency-access'", false)
	}
	if input.IdempotencyKey == "" || !protocol.ValidIdempotencyKey(input.IdempotencyKey) {
		return protocol.Fail(protocol.ErrorInvalidInput, "idempotencyKey is required", false)
	}
	if _, err := git.ValidateRepositoryURL(input.RepositoryURL, s.cfg.AllowedGitHosts); err != nil {
		return failFrom(err)
	}
	profile := s.cfg.NetworkProfile
	if input.NetworkProfile != "" {
		profile = protocol.NetworkProfile(input.NetworkProfile)
		if !profile.Valid() {
			return protocol.Fail(protocol.ErrorInvalidInput, "networkProfile must be 'network-none' or 'dependency-access'", false)
		}
	}
	if err := sandbox.EnsureProfileReady(ctx, profile, s.cfg.Attestor); err != nil {
		return failFrom(err)
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	if existing, ok := s.store.ByIdempotency(ownerID, input.IdempotencyKey); ok {
		return protocol.Success("workspace already open", publicRecord(existing))
	}
	now := time.Now()
	rec := store.Record{
		ID:             protocol.NewOpaqueID(protocol.PrefixWorkspace),
		OwnerID:        ownerID,
		RepositoryURL:  input.RepositoryURL,
		Ref:            input.Ref,
		Status:         store.StatusCreating,
		NetworkProfile: profile,
		IdempotencyKey: input.IdempotencyKey,
		Fingerprint:    fingerprint(input, profile),
		Generation:     1,
		CreatedAt:      now,
		LastActivityAt: now,
		ExpiresAt:      now.Add(s.cfg.IdleTTL),
		HardExpiresAt:  now.Add(s.cfg.WallTTL),
	}
	name, err := s.engine.Create(ctx, rec)
	if err != nil {
		rec.Status = store.StatusFailed
		_ = s.store.Put(rec)
		return protocol.Fail(protocol.ErrorUnavailable, "executor creation failed", true)
	}
	rec.ContainerName = name
	rec.Status = store.StatusActive
	_ = s.store.Put(rec)
	return protocol.Success("workspace opened", publicRecord(rec))
}

func (s *Service) list(req protocol.RunnerRequest) protocol.ToolResult {
	ownerID := req.OwnerID
	records := s.store.List(ownerID)
	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		items = append(items, publicRecord(rec))
	}
	return protocol.Success("workspaces", map[string]any{"workspaces": items})
}

type idInput struct {
	WorkspaceID string `json:"workspaceId"`
}

func (s *Service) status(req protocol.RunnerRequest) protocol.ToolResult {
	var input idInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	rec, ok := s.store.Get(input.WorkspaceID)
	if !ok {
		return protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
	}
	return protocol.Success("workspace status", publicRecord(rec))
}

func (s *Service) close(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	var input idInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	rec, ok := s.store.Get(input.WorkspaceID)
	if !ok {
		return protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
	}
	if rec.ContainerName != "" {
		_ = s.engine.Remove(ctx, rec.ContainerName)
	}
	rec, _ = s.store.UpdateStatus(rec.ID, store.StatusClosed)
	return protocol.Success("workspace closed", publicRecord(rec))
}

func publicRecord(rec store.Record) map[string]any {
	return map[string]any{
		"workspaceId":      rec.ID,
		"repositoryUrl":    rec.RepositoryURL,
		"ref":              rec.Ref,
		"status":           string(rec.Status),
		"networkProfile":   string(rec.NetworkProfile),
		"generation":       rec.Generation,
		"createdAt":        rec.CreatedAt.UTC().Format(time.RFC3339Nano),
		"lastActivityAt":   rec.LastActivityAt.UTC().Format(time.RFC3339Nano),
		"expiresAt":        rec.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"hardExpiresAt":    rec.HardExpiresAt.UTC().Format(time.RFC3339Nano),
		"remainingLeaseMs": maxInt64(0, time.Until(rec.ExpiresAt).Milliseconds()),
	}
}

func fingerprint(input openInput, profile protocol.NetworkProfile) string {
	payload, _ := json.Marshal(map[string]any{
		"repositoryUrl":  input.RepositoryURL,
		"ref":            emptyToNil(input.Ref),
		"environmentId":  emptyToNil(input.EnvironmentID),
		"networkProfile": string(profile),
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func emptyToNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func failFrom(err error) protocol.ToolResult {
	msg := err.Error()
	code := protocol.ErrorInternal
	for _, candidate := range []protocol.ErrorCode{
		protocol.ErrorInvalidInput,
		protocol.ErrorForbidden,
		protocol.ErrorDependencyEgressUnavailable,
		protocol.ErrorUnavailable,
	} {
		if strings.HasPrefix(msg, string(candidate)+":") {
			code = candidate
			msg = strings.TrimSpace(strings.TrimPrefix(msg, string(candidate)+":"))
			break
		}
	}
	retryable := code == protocol.ErrorUnavailable
	return protocol.Fail(code, msg, retryable)
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
