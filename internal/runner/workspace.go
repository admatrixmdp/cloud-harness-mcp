package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
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
	JobsRoot        string
	ExecutorImage   string
	GitHubApp       git.AppConfig
	HTTP            *http.Client
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
	if c.ExecutorImage == "" {
		c.ExecutorImage = "cloud-harness-executor:local"
	}
	return c
}

// Service executes public runner operations.
type Service struct {
	cfg    Config
	store  store.Store
	engine Engine
	cloner *git.Cloner
}

// WithCloner clones through a helper container after executor create.
// The minted token rides helper stdin only and never appears in argv or MCP results.
func (s *Service) WithCloner(c *git.Cloner) *Service {
	s.cloner = c
	return s
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
	case protocol.OpWorkspaceLeaseRenew:
		return s.renew(req)
	case protocol.OpWorkspaceRecover:
		return s.recover(ctx, req)
	case protocol.OpWorkspaceContext:
		return s.contextOf(req)
	case protocol.OpWorkspaceSetActive:
		return s.setActive(req)
	case protocol.OpGitIdentityStatus:
		return s.gitIdentityStatus(req)
	case protocol.OpGitIdentitySet:
		return s.gitIdentitySet(req)
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
	parsed, err := git.ValidateRepositoryURL(input.RepositoryURL, s.cfg.AllowedGitHosts)
	if err != nil {
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
	if err := s.cloneIntoJob(ctx, rec, parsed); err != nil {
		_ = s.engine.Remove(ctx, name)
		rec.Status = store.StatusFailed
		_ = s.store.Put(rec)
		return failFrom(err)
	}
	rec.Status = store.StatusActive
	_ = s.store.Put(rec)
	return protocol.Success("workspace opened", publicRecord(rec))
}

func (s *Service) cloneIntoJob(ctx context.Context, rec store.Record, parsed *url.URL) error {
	if s.cloner == nil {
		return nil
	}
	if s.cfg.JobsRoot == "" {
		return nil
	}
	minted, err := git.MintRepositoryToken(s.cfg.GitHubApp, parsed, s.cfg.HTTP, time.Now())
	if err != nil {
		return err
	}
	spec := git.HelperSpec{
		Name:          "chm-clone-" + rec.ID[3:minLen(rec.ID, 15)],
		Image:         s.cfg.ExecutorImage,
		InstanceID:    s.cfg.InstanceID,
		WorkspaceID:   rec.ID,
		JobPath:       filepath.Join(s.cfg.JobsRoot, rec.ID),
		RepositoryURL: rec.RepositoryURL,
		Ref:           rec.Ref,
	}
	_, err = s.cloner.Run(ctx, git.CloneRequest{Spec: spec, Token: minted.Stdin()})
	return err
}

func minLen(s string, n int) int {
	if len(s) < n {
		return len(s)
	}
	return n
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

type renewInput struct {
	WorkspaceID      string `json:"workspaceId"`
	ExtensionSeconds int    `json:"extensionSeconds"`
}

func (s *Service) renew(req protocol.RunnerRequest) protocol.ToolResult {
	var input renewInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	if input.ExtensionSeconds != 0 && (input.ExtensionSeconds < 60 || input.ExtensionSeconds > 86400) {
		return protocol.Fail(protocol.ErrorInvalidInput, "extensionSeconds must be between 60 and 86400", false)
	}
	rec, ok := s.store.Get(input.WorkspaceID)
	if !ok {
		return protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
	}
	if rec.Status == store.StatusClosed || rec.Status == store.StatusFailed {
		return protocol.Fail(protocol.ErrorExpired, "workspace is "+strings.ToLower(string(rec.Status))+" and cannot be renewed", false)
	}
	if rec.Status == store.StatusCreating || rec.Status == store.StatusReaping {
		return protocol.Fail(protocol.ErrorConflict, "workspace is "+strings.ToLower(string(rec.Status)), true)
	}
	now := time.Now()
	if !rec.HardExpiresAt.After(now) {
		return protocol.Fail(protocol.ErrorExpired, "Workspace hard lease limit reached and cannot be renewed", false)
	}
	ext := s.cfg.IdleTTL
	if input.ExtensionSeconds > 0 {
		ext = time.Duration(input.ExtensionSeconds) * time.Second
	}
	expires := now.Add(ext)
	if expires.After(rec.HardExpiresAt) {
		expires = rec.HardExpiresAt
	}
	updated, ok := s.store.RenewLease(rec.ID, expires, now)
	if !ok {
		return protocol.Fail(protocol.ErrorConflict, "workspace lifecycle changed during renewal", true)
	}
	return protocol.Success("workspace lease renewed", publicRecord(updated))
}

type recoverInput struct {
	WorkspaceID string `json:"workspaceId"`
	Mode        string `json:"mode"`
}

func (s *Service) recover(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	_ = ctx
	var input recoverInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	mode := input.Mode
	if mode == "" {
		mode = "resume"
	}
	switch mode {
	case "resume", "status", "patch", "export":
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "mode must be resume, status, patch, or export", false)
	}
	rec, errRes := s.requireOwned(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	if rec.Status == store.StatusClosed || rec.Status == store.StatusFailed {
		return protocol.Fail(protocol.ErrorExpired, "workspace is "+strings.ToLower(string(rec.Status))+" and cannot be recovered", false)
	}
	if rec.Status == store.StatusCreating || rec.Status == store.StatusReaping {
		return protocol.Fail(protocol.ErrorConflict, "workspace is "+strings.ToLower(string(rec.Status)), true)
	}
	if mode != "resume" {
		return protocol.Fail(protocol.ErrorUnavailable, "workspace_recover mode "+mode+" is not wired in this Go-port slice", true)
	}
	now := time.Now()
	if !rec.HardExpiresAt.After(now) {
		return protocol.Fail(protocol.ErrorExpired, "Workspace hard lease limit reached and cannot be recovered to active state; use mode: export to save work", false)
	}
	expires := now.Add(s.cfg.IdleTTL)
	if expires.After(rec.HardExpiresAt) {
		expires = rec.HardExpiresAt
	}
	updated, ok := s.store.Activate(rec.ID, expires, now)
	if !ok {
		return protocol.Fail(protocol.ErrorConflict, "workspace lifecycle changed during recovery", true)
	}
	return protocol.Success("Workspace recovered to active state", publicRecord(updated))
}

func (s *Service) contextOf(req protocol.RunnerRequest) protocol.ToolResult {
	var input idInput
	if len(req.Input) > 0 {
		_ = json.Unmarshal(req.Input, &input)
	}
	rec, errRes := s.resolveWorkspace(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	name, email, ok := s.store.GitIdentity(rec.OwnerID)
	source := "owner"
	if !ok {
		name, email, source = "Cloud Harness Agent", "agent@cloud-harness.local", "default"
	}
	data := publicRecord(rec)
	data["gitIdentity"] = map[string]any{"name": name, "email": email, "source": source}
	return protocol.Success("workspace context", data)
}

func (s *Service) setActive(req protocol.RunnerRequest) protocol.ToolResult {
	var input idInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	rec, errRes := s.requireOwned(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	active := 0
	for _, sibling := range s.store.List(rec.OwnerID) {
		if sibling.Status == store.StatusActive || sibling.Status == store.StatusCreating {
			active++
		}
	}
	isActive := rec.Status == store.StatusActive || rec.Status == store.StatusCreating
	isRecoverable := rec.Status == store.StatusExpiredRecoverable || rec.Status == store.StatusNetworkQuarantined
	if isActive && active > 1 {
		return protocol.Fail(protocol.ErrorConflict, "more than one active workspace exists; pass workspaceId on each call instead of setting a default", true)
	}
	if isRecoverable && active > 0 {
		return protocol.Fail(protocol.ErrorConflict, "an active workspace exists, so a recoverable workspace cannot become the default; pass workspaceId explicitly", true)
	}
	if !isActive && !isRecoverable {
		return protocol.Fail(protocol.ErrorConflict, "workspace is "+strings.ToLower(string(rec.Status))+" and cannot be set as the active workspace", true)
	}
	s.store.SetPreferredWorkspace(rec.OwnerID, rec.ID)
	return protocol.Success("Active workspace set", map[string]any{
		"activeWorkspaceId": rec.ID,
		"workspace":         publicRecord(rec),
	})
}

func (s *Service) gitIdentityStatus(req protocol.RunnerRequest) protocol.ToolResult {
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	name, email, ok := s.store.GitIdentity(ownerID)
	source := "owner"
	if !ok {
		name, email, source = "Cloud Harness Agent", "agent@cloud-harness.local", "default"
	}
	return protocol.Success("Git identity status", map[string]any{
		"name":   name,
		"email":  email,
		"source": source,
	})
}

type identityInput struct {
	WorkspaceID string `json:"workspaceId"`
	Name        string `json:"name"`
	Email       string `json:"email"`
}

func (s *Service) gitIdentitySet(req protocol.RunnerRequest) protocol.ToolResult {
	var input identityInput
	if err := json.Unmarshal(req.Input, &input); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid git_identity_set input", false)
	}
	if strings.TrimSpace(input.Name) == "" || len(input.Name) > 200 {
		return protocol.Fail(protocol.ErrorInvalidInput, "name is required", false)
	}
	if !strings.Contains(input.Email, "@") || strings.ContainsAny(input.Email, " \n") {
		return protocol.Fail(protocol.ErrorInvalidInput, "email is required", false)
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	if input.WorkspaceID != "" {
		if _, errRes := s.requireOwned(ownerID, input.WorkspaceID); errRes != nil {
			return *errRes
		}
	}
	s.store.SetGitIdentity(ownerID, input.Name, input.Email)
	return protocol.Success("Git identity configured", map[string]any{"name": input.Name, "email": input.Email})
}

func (s *Service) requireOwned(ownerID, workspaceID string) (store.Record, *protocol.ToolResult) {
	rec, ok := s.store.Get(workspaceID)
	if !ok {
		fail := protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
		return store.Record{}, &fail
	}
	if ownerID != "" && rec.OwnerID != ownerID {
		fail := protocol.Fail(protocol.ErrorForbidden, "workspace access not authorized", false)
		return store.Record{}, &fail
	}
	return rec, nil
}

func (s *Service) resolveWorkspace(ownerID, workspaceID string) (store.Record, *protocol.ToolResult) {
	if workspaceID != "" {
		return s.requireOwned(ownerID, workspaceID)
	}
	if preferred, ok := s.store.PreferredWorkspace(ownerID); ok {
		return s.requireOwned(ownerID, preferred)
	}
	var candidates []store.Record
	for _, rec := range s.store.List(ownerID) {
		if rec.Status == store.StatusActive || rec.Status == store.StatusCreating {
			candidates = append(candidates, rec)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) > 1 {
		fail := protocol.Fail(protocol.ErrorConflict, "Multiple active workspaces found. Specify workspaceId on each call.", true)
		return store.Record{}, &fail
	}
	fail := protocol.Fail(protocol.ErrorNotFound, "workspace not found", false)
	return store.Record{}, &fail
}

func publicRecord(rec store.Record) map[string]any {
	now := time.Now()
	remaining := maxInt64(0, rec.ExpiresAt.Sub(now).Milliseconds())
	hardRemaining := maxInt64(0, rec.HardExpiresAt.Sub(now).Milliseconds())
	canRenew := (rec.Status == store.StatusActive || rec.Status == store.StatusExpiredRecoverable) && hardRemaining > 60_000
	leaseState := "ACTIVE"
	switch rec.Status {
	case store.StatusExpiredRecoverable:
		leaseState = "EXPIRED_RECOVERABLE"
	case store.StatusNetworkQuarantined, store.StatusClosed, store.StatusFailed:
		leaseState = "EXPIRED"
	default:
		if remaining <= 300_000 && rec.Status == store.StatusActive {
			leaseState = "WARNING"
		}
	}
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
		"idleExpiresAt":    rec.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"hardExpiresAt":    rec.HardExpiresAt.UTC().Format(time.RFC3339Nano),
		"remainingLeaseMs": remaining,
		"canRenewLease":    canRenew,
		"leaseState":       leaseState,
		"availableActions": availableActions(rec.Status, canRenew),
	}
}

func availableActions(status store.Status, canRenew bool) []string {
	switch status {
	case store.StatusActive:
		if canRenew {
			return []string{"workspace_lease_renew", "workspace_close", "workspace_context", "workspace_finalize"}
		}
		return []string{"workspace_close", "workspace_context", "workspace_finalize"}
	case store.StatusExpiredRecoverable:
		if canRenew {
			return []string{"workspace_recover", "workspace_lease_renew", "workspace_close"}
		}
		return []string{"workspace_recover", "workspace_close"}
	case store.StatusNetworkQuarantined:
		return []string{"workspace_recover", "workspace_close", "workspace_context"}
	case store.StatusCreating, store.StatusReaping:
		return []string{"workspace_status"}
	case store.StatusClosed, store.StatusFailed:
		return []string{"workspace_open"}
	default:
		return []string{}
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
