package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/executor"
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
	case protocol.OpGitFetch:
		return s.gitFetch(ctx, req)
	case protocol.OpGitPull:
		return s.gitPull(ctx, req)
	case protocol.OpGitPush:
		return s.gitPush(ctx, req)
	case protocol.OpGitHubAction, protocol.OpGitHubRead:
		return s.githubCall(ctx, req)
	case protocol.OpFilesList, protocol.OpFilesRead, protocol.OpFilesWrite, protocol.OpFilesWriteBatch, protocol.OpFilesApplyPatch, protocol.OpFilesDelete, protocol.OpFilesMove, protocol.OpFilesMkdir, protocol.OpGrepSearch, protocol.OpSymbolsSearch, protocol.OpSymbolsReferences, protocol.OpExecRun, protocol.OpGitStatus, protocol.OpGitDiff, protocol.OpGitLog, protocol.OpGitBranch, protocol.OpGitCheckout, protocol.OpGitAdd, protocol.OpGitCommit, protocol.OpGitMerge, protocol.OpGitRebase:
		return s.runWorker(ctx, req)
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
	WorkspaceID  string `json:"workspaceId"`
	Mode         string `json:"mode"`
	TargetBranch string `json:"targetBranch"`
}

func (s *Service) recover(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
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
	switch mode {
	case "status", "patch":
		got := s.recoverWorker(ctx, rec, mode, "")
		if !got.OK {
			return got
		}
		data := map[string]any{"workspace": publicRecord(rec)}
		if extra, ok := got.Data.(map[string]any); ok {
			for k, v := range extra {
				data[k] = v
			}
		}
		return protocol.Success(got.Message, data)
	case "export":
		return s.recoverExport(ctx, rec, input.TargetBranch)
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

func (s *Service) recoverWorker(ctx context.Context, rec store.Record, mode, message string) protocol.ToolResult {
	if s.cfg.JobsRoot == "" {
		return protocol.Fail(protocol.ErrorUnavailable, "workspace recovery worker is not configured", true)
	}
	payload, err := json.Marshal(map[string]any{"mode": mode, "message": message})
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, "could not encode recovery worker input", false)
	}
	return s.executeInJob(ctx, rec, protocol.OpWorkspaceRecover, payload)
}

func (s *Service) runWorker(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	var loc struct {
		WorkspaceID string `json:"workspaceId"`
	}
	if len(req.Input) > 0 {
		_ = json.Unmarshal(req.Input, &loc)
	}
	rec, errRes := s.resolveWorkspace(req.OwnerID, loc.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	if fail := s.requireActiveExecutor(rec); fail != nil {
		return *fail
	}
	input := req.Input
	if req.Operation == protocol.OpGitCommit {
		input = s.withGitIdentity(rec.OwnerID, input)
	}
	return s.executeInJob(ctx, rec, req.Operation, input)
}

func (s *Service) requireActiveExecutor(rec store.Record) *protocol.ToolResult {
	switch rec.Status {
	case store.StatusClosed, store.StatusFailed:
		fail := protocol.Fail(protocol.ErrorExpired, "workspace is "+strings.ToLower(string(rec.Status))+" and cannot run executor operations", false)
		return &fail
	case store.StatusExpiredRecoverable:
		fail := protocol.Fail(protocol.ErrorExpired, "workspace is expired and in recoverable grace state; use workspace_recover or workspace_lease_renew", false)
		return &fail
	case store.StatusNetworkQuarantined:
		fail := protocol.Fail(protocol.ErrorDependencyEgressUnavailable, "workspace is quarantined due to network security policy drift; use workspace_recover after policy reconciliation or workspace_close", false)
		return &fail
	case store.StatusCreating, store.StatusReaping:
		fail := protocol.Fail(protocol.ErrorConflict, "workspace is "+strings.ToLower(string(rec.Status)), true)
		return &fail
	}
	if s.cfg.JobsRoot == "" {
		fail := protocol.Fail(protocol.ErrorUnavailable, "workspace executor is not configured", true)
		return &fail
	}
	return nil
}

func (s *Service) executeInJob(ctx context.Context, rec store.Record, op protocol.Operation, input json.RawMessage) protocol.ToolResult {
	root := filepath.Join(s.cfg.JobsRoot, rec.ID, "repo")
	return (executor.Workspace{Root: root}).Execute(ctx, op, input)
}

func (s *Service) withGitIdentity(ownerID string, input json.RawMessage) json.RawMessage {
	fields := map[string]any{}
	if len(input) > 0 {
		_ = json.Unmarshal(input, &fields)
	}
	if _, ok := fields["authorName"].(string); ok {
		if _, ok := fields["authorEmail"].(string); ok {
			return input
		}
	}
	name, email, ok := s.store.GitIdentity(ownerID)
	if !ok {
		name, email = "Cloud Harness Agent", "agent@cloud-harness.local"
	}
	if _, exists := fields["authorName"]; !exists {
		fields["authorName"] = name
	}
	if _, exists := fields["authorEmail"]; !exists {
		fields["authorEmail"] = email
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return input
	}
	return raw
}

func (s *Service) recoverExport(ctx context.Context, rec store.Record, targetBranch string) protocol.ToolResult {
	if targetBranch == "" {
		targetBranch = rec.Ref
	}
	if targetBranch == "" {
		targetBranch = "main"
	}
	if !git.ValidFetchRef(targetBranch) {
		return protocol.Fail(protocol.ErrorInvalidInput, "targetBranch cannot start with a dash", false)
	}
	snapshot := s.recoverWorker(ctx, rec, "snapshot_commit", "chore(recovery): export snapshot for "+targetBranch)
	if !snapshot.OK {
		if snapshot.Error.Code == protocol.ErrorUnavailable || snapshot.Error.Code == protocol.ErrorInvalidInput {
			return snapshot
		}
		return protocol.Fail(protocol.ErrorInternal, "Recovery snapshot failed: "+snapshot.Message, true)
	}
	refspec, err := git.NormalizePushRefspec("HEAD:refs/heads/"+targetBranch, targetBranch)
	if err != nil {
		return failFrom(err)
	}
	out, err := s.remotePush(ctx, rec, refspec, "")
	if err != nil {
		return failFrom(err)
	}
	data := map[string]any{
		"workspace": publicRecord(rec),
		"branch":    targetBranch,
		"pushResult": map[string]any{
			"output": out,
		},
	}
	if extra, ok := snapshot.Data.(map[string]any); ok {
		if sha, ok := extra["headCommitSha"].(string); ok {
			data["commitSha"] = sha
		}
		if committed, ok := extra["committedChanges"].(bool); ok {
			data["committedChanges"] = committed
		}
	}
	return protocol.Success("Recovered work exported to "+targetBranch, data)
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

type fetchInput struct {
	WorkspaceID  string `json:"workspaceId"`
	Remote       string `json:"remote"`
	Refspec      string `json:"refspec"`
	Depth        *int   `json:"depth"`
	Unshallow    bool   `json:"unshallow"`
	ShallowSince string `json:"shallowSince"`
}

func (s *Service) gitFetch(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	var input fetchInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	if input.Remote != "" && input.Remote != "origin" {
		return protocol.Fail(protocol.ErrorInvalidInput, "remote must be origin", false)
	}
	if input.Refspec != "" && !git.ValidFetchRef(input.Refspec) {
		return protocol.Fail(protocol.ErrorInvalidInput, "Git fetch ref cannot contain a destination", false)
	}
	rec, errRes := s.requireOwned(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	history, err := git.FetchHistorySpec(input.Depth, input.Unshallow, input.ShallowSince)
	if err != nil {
		return failFrom(err)
	}
	out, err := s.remoteFetch(ctx, rec, input.Refspec, history)
	if err != nil {
		return failFrom(err)
	}
	return protocol.Success("Git fetch complete", map[string]any{"output": out})
}

type pullInput struct {
	WorkspaceID string `json:"workspaceId"`
	Remote      string `json:"remote"`
	Branch      string `json:"branch"`
	Strategy    string `json:"strategy"`
}

func (s *Service) gitPull(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	var input pullInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	if input.Remote != "" && input.Remote != "origin" {
		return protocol.Fail(protocol.ErrorInvalidInput, "remote must be origin", false)
	}
	if input.Branch != "" && !git.ValidFetchRef(input.Branch) {
		return protocol.Fail(protocol.ErrorInvalidInput, "branch cannot start with a dash", false)
	}
	strategy := input.Strategy
	if strategy == "" {
		strategy = "ff-only"
	}
	switch strategy {
	case "ff-only", "merge", "rebase":
	default:
		return protocol.Fail(protocol.ErrorInvalidInput, "strategy must be ff-only, merge, or rebase", false)
	}
	rec, errRes := s.requireOwned(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	ref := input.Branch
	if ref != "" {
		ref = "refs/heads/" + ref
	}
	if _, err := s.remoteFetch(ctx, rec, ref, ""); err != nil {
		return failFrom(err)
	}
	return protocol.Success("Git pull complete", map[string]any{"strategy": strategy})
}

type pushInput struct {
	WorkspaceID       string `json:"workspaceId"`
	Remote            string `json:"remote"`
	Refspec           string `json:"refspec"`
	ForceWithLease    bool   `json:"forceWithLease"`
	ExpectedRemoteOid string `json:"expectedRemoteOid"`
}

func (s *Service) gitPush(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	var input pushInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	if input.Remote != "" && input.Remote != "origin" {
		return protocol.Fail(protocol.ErrorInvalidInput, "remote must be origin", false)
	}
	if input.ForceWithLease && input.ExpectedRemoteOid == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "expectedRemoteOid is required with forceWithLease", false)
	}
	if !input.ForceWithLease && input.ExpectedRemoteOid != "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "expectedRemoteOid is only valid with forceWithLease", false)
	}
	rec, errRes := s.requireOwned(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	refspec, err := git.NormalizePushRefspec(input.Refspec, rec.Ref)
	if err != nil {
		return failFrom(err)
	}
	out, err := s.remotePush(ctx, rec, refspec, input.ExpectedRemoteOid)
	if err != nil {
		return failFrom(err)
	}
	return protocol.Success("Git push complete", map[string]any{"output": out, "refspec": refspec})
}

func (s *Service) remoteFetch(ctx context.Context, rec store.Record, remoteRef, history string) (string, error) {
	if s.cloner == nil {
		return "", fmt.Errorf("%s: git transfer helper is not configured", protocol.ErrorUnavailable)
	}
	parsed, err := git.ValidateRepositoryURL(rec.RepositoryURL, s.cfg.AllowedGitHosts)
	if err != nil {
		return "", err
	}
	if err := git.ValidateHistorySpec(history); err != nil {
		return "", err
	}
	minted, err := git.MintRepositoryToken(s.cfg.GitHubApp, parsed, s.cfg.HTTP, time.Now())
	if err != nil {
		return "", err
	}
	transferName := "git-transfer-" + rec.ID[3:minLen(rec.ID, 15)]
	spec := git.HelperSpec{
		Name:          "chm-git-fetch-" + rec.ID[3:minLen(rec.ID, 15)],
		Image:         s.cfg.ExecutorImage,
		InstanceID:    s.cfg.InstanceID,
		WorkspaceID:   rec.ID,
		JobPath:       filepath.Join(s.cfg.JobsRoot, rec.ID),
		RepositoryURL: rec.RepositoryURL,
		TransferName:  transferName,
		Argument:      remoteRef,
		HistorySpec:   history,
	}
	fetched, err := s.cloner.Transfer(ctx, git.TransferFetch, spec, minted.Stdin())
	if err != nil {
		return "", err
	}
	spec.Name = "chm-git-import-" + rec.ID[3:minLen(rec.ID, 15)]
	imported, err := s.cloner.Transfer(ctx, git.TransferImport, spec, "")
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(imported.Stdout + "\n" + fetched.Stdout)
	return out, nil
}

func (s *Service) remotePush(ctx context.Context, rec store.Record, refspec, expectedOID string) (string, error) {
	if s.cloner == nil {
		return "", fmt.Errorf("%s: git transfer helper is not configured", protocol.ErrorUnavailable)
	}
	parsed, err := git.ValidateRepositoryURL(rec.RepositoryURL, s.cfg.AllowedGitHosts)
	if err != nil {
		return "", err
	}
	minted, err := git.MintRepositoryToken(s.cfg.GitHubApp, parsed, s.cfg.HTTP, time.Now())
	if err != nil {
		return "", err
	}
	if minted.Token == "" {
		return "", fmt.Errorf("%s: Git push requires a configured GitHub App with repository write access", protocol.ErrorRepositoryOperationNotAuthorized)
	}
	transferName := "git-transfer-" + rec.ID[3:minLen(rec.ID, 15)]
	spec := git.HelperSpec{
		Name:          "chm-git-push-" + rec.ID[3:minLen(rec.ID, 15)],
		Image:         s.cfg.ExecutorImage,
		InstanceID:    s.cfg.InstanceID,
		WorkspaceID:   rec.ID,
		JobPath:       filepath.Join(s.cfg.JobsRoot, rec.ID),
		RepositoryURL: rec.RepositoryURL,
		TransferName:  transferName,
		Argument:      refspec,
		ExpectedOID:   expectedOID,
	}
	res, err := s.cloner.Transfer(ctx, git.TransferPush, spec, minted.Stdin())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

type githubInput struct {
	WorkspaceID  string   `json:"workspaceId"`
	Action       string   `json:"action"`
	Limit        int      `json:"limit"`
	State        string   `json:"state"`
	PRNumber     int      `json:"prNumber"`
	IssueNumber  int      `json:"issueNumber"`
	CommentID    int      `json:"commentId"`
	Title        string   `json:"title"`
	Body         string   `json:"body"`
	Head         string   `json:"head"`
	Base         string   `json:"base"`
	Draft        bool     `json:"draft"`
	Labels       []string `json:"labels"`
	Assignees    []string `json:"assignees"`
	Name         string   `json:"name"`
	Color        string   `json:"color"`
	Description  string   `json:"description"`
	Label        string   `json:"label"`
	SHA          string   `json:"sha"`
	Path         string   `json:"path"`
	Since        string   `json:"since"`
	Until        string   `json:"until"`
	AddLabels    []string `json:"addLabels"`
	RemoveLabels []string `json:"removeLabels"`
	StateReason  string   `json:"stateReason"`
	Comment      string   `json:"comment"`
}

func (s *Service) githubCall(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	var input githubInput
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
	}
	perm, ok := git.RequiredGitHubPermissions(input.Action)
	if !ok {
		return protocol.Fail(protocol.ErrorInvalidInput, "unsupported github_action: "+input.Action, false)
	}
	if req.Operation == protocol.OpGitHubRead && perm.Write {
		return protocol.Fail(protocol.ErrorInvalidInput, "github_read accepts read-only actions only; use github_action for "+input.Action, false)
	}
	rec, errRes := s.requireOwned(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	if s.cloner == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "github helper is not configured", true)
	}
	parsed, err := git.ValidateRepositoryURL(rec.RepositoryURL, s.cfg.AllowedGitHosts)
	if err != nil {
		return failFrom(err)
	}
	minted, err := git.MintRepositoryToken(s.cfg.GitHubApp, parsed, s.cfg.HTTP, time.Now())
	if err != nil {
		return failFrom(err)
	}
	if minted.Token == "" {
		return protocol.Fail(protocol.ErrorRepositoryOperationNotAuthorized, string(req.Operation)+" requires a configured GitHub App", false)
	}
	args, err := githubHelperArgs(input)
	if err != nil {
		return failFrom(err)
	}
	spec := git.HelperSpec{
		Name:          "chm-gh-" + rec.ID[3:minLen(rec.ID, 15)],
		Image:         s.cfg.ExecutorImage,
		InstanceID:    s.cfg.InstanceID,
		WorkspaceID:   rec.ID,
		JobPath:       filepath.Join(s.cfg.JobsRoot, rec.ID),
		RepositoryURL: rec.RepositoryURL,
		Action:        input.Action,
		ActionArgs:    args,
	}
	res, err := s.cloner.GH(ctx, spec, minted.Stdin())
	if err != nil {
		return failFrom(err)
	}
	out := git.RedactToken(strings.TrimSpace(res.Stdout+"\n"+res.Stderr), minted.Token)
	if res.ExitCode != 0 {
		return protocol.Fail(protocol.ErrorGitHubActionFailed, "GitHub helper failed", false)
	}
	return protocol.Success("GitHub "+input.Action+" complete", map[string]any{"output": out, "action": input.Action})
}

func githubHelperArgs(in githubInput) ([]string, error) {
	join := func(items []string) string { return strings.Join(items, ",") }
	switch in.Action {
	case "pr_list", "issue_list":
		limit := in.Limit
		if limit == 0 {
			limit = 20
		}
		state := in.State
		if state == "" {
			state = "open"
		}
		return []string{fmt.Sprintf("%d", limit), state}, nil
	case "pr_view":
		return []string{fmt.Sprintf("%d", in.PRNumber)}, nil
	case "issue_view":
		return []string{fmt.Sprintf("%d", in.IssueNumber)}, nil
	case "pr_create":
		if in.Title == "" || in.Head == "" {
			return nil, fmt.Errorf("%s: title and head are required", protocol.ErrorInvalidInput)
		}
		base := in.Base
		if base == "" {
			base = "main"
		}
		return []string{in.Title, in.Body, in.Head, base, fmt.Sprintf("%t", in.Draft), join(in.Labels)}, nil
	case "pr_update":
		return []string{fmt.Sprintf("%d", in.PRNumber), in.Title, in.Body, in.Base, in.State}, nil
	case "pr_comment":
		return []string{fmt.Sprintf("%d", in.PRNumber), in.Body}, nil
	case "issue_create":
		if in.Title == "" {
			return nil, fmt.Errorf("%s: title is required", protocol.ErrorInvalidInput)
		}
		return []string{in.Title, in.Body, join(in.Labels), join(in.Assignees)}, nil
	case "issue_comment":
		return []string{fmt.Sprintf("%d", in.IssueNumber), in.Body}, nil
	case "issue_comment_update":
		return []string{fmt.Sprintf("%d", in.CommentID), in.Body}, nil
	case "label_create":
		color := in.Color
		if color == "" {
			color = "0E8A16"
		}
		return []string{in.Name, color, in.Description}, nil
	case "issue_labels_add":
		return []string{fmt.Sprintf("%d", in.IssueNumber), join(in.Labels), "true"}, nil
	case "issue_labels_remove":
		return []string{fmt.Sprintf("%d", in.IssueNumber), in.Label}, nil
	case "issue_update":
		return []string{fmt.Sprintf("%d", in.IssueNumber), in.Title, in.Body, in.State, in.StateReason}, nil
	case "issue_publish":
		return []string{fmt.Sprintf("%d", in.IssueNumber), in.Comment, join(in.AddLabels), join(in.RemoveLabels), "true"}, nil
	case "commit_list":
		limit := in.Limit
		if limit == 0 {
			limit = 30
		}
		return []string{fmt.Sprintf("%d", limit), in.SHA, in.Path, in.Since, in.Until}, nil
	case "compare":
		if in.Base == "" || in.Head == "" {
			return nil, fmt.Errorf("%s: base and head are required", protocol.ErrorInvalidInput)
		}
		limit := in.Limit
		if limit == 0 {
			limit = 100
		}
		return []string{in.Base, in.Head, fmt.Sprintf("%d", limit)}, nil
	case "release_list":
		limit := in.Limit
		if limit == 0 {
			limit = 20
		}
		return []string{fmt.Sprintf("%d", limit)}, nil
	case "tag_list":
		limit := in.Limit
		if limit == 0 {
			limit = 30
		}
		return []string{fmt.Sprintf("%d", limit)}, nil
	default:
		return nil, fmt.Errorf("%s: unsupported github_action: %s", protocol.ErrorInvalidInput, in.Action)
	}
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
		protocol.ErrorRepositoryOperationNotAuthorized,
		protocol.ErrorConflict,
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
