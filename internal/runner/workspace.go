package runner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bestagentkits/cloud-harness-mcp/internal/artifacts"
	"github.com/bestagentkits/cloud-harness-mcp/internal/executor"
	"github.com/bestagentkits/cloud-harness-mcp/internal/git"
	"github.com/bestagentkits/cloud-harness-mcp/internal/grants"
	"github.com/bestagentkits/cloud-harness-mcp/internal/hooks"
	"github.com/bestagentkits/cloud-harness-mcp/internal/knowledge"
	"github.com/bestagentkits/cloud-harness-mcp/internal/memories"
	"github.com/bestagentkits/cloud-harness-mcp/internal/sandbox"
	"github.com/bestagentkits/cloud-harness-mcp/internal/secrets"
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
	cfg       Config
	store     store.Store
	engine    Engine
	cloner    *git.Cloner
	secrets   *secrets.Store
	artifacts *artifacts.Store
	memories  *memories.Store
	knowledge *knowledge.Store
	hooks     *hooks.Store
	grants    *grants.Store
	agents    *agentHub
	docker    *sandbox.Engine
}

// WithCloner clones through a helper container after executor create.
// The minted token rides helper stdin only and never appears in argv or MCP results.
func (s *Service) WithCloner(c *git.Cloner) *Service {
	s.cloner = c
	return s
}

// WithSecrets attaches the runner keyring metadata store. secrets_list never
// decrypts or returns plaintext.
func (s *Service) WithSecrets(sec *secrets.Store) *Service {
	s.secrets = sec
	return s
}

// WithArtifacts attaches retained snapshot storage. Local stdio never hosts this.
func (s *Service) WithArtifacts(store *artifacts.Store) *Service {
	s.artifacts = store
	return s
}

// WithMemories attaches retained SQLite memory notes. Local stdio uses confined markdown instead.
func (s *Service) WithMemories(store *memories.Store) *Service {
	s.memories = store
	return s
}

// WithKnowledge attaches retained SQLite knowledge items. Local stdio never hosts this.
func (s *Service) WithKnowledge(store *knowledge.Store) *Service {
	s.knowledge = store
	return s
}

// WithHooks attaches retained lifecycle-hook activations. Local stdio never hosts this.
func (s *Service) WithHooks(store *hooks.Store) *Service {
	s.hooks = store
	return s
}

// WithGrants attaches owner privilege grants. skills_run on the runner requires one.
func (s *Service) WithGrants(store *grants.Store) *Service {
	s.grants = store
	return s
}

// WithDocker attaches the runner Docker CLI used for disposable skill helpers.
func (s *Service) WithDocker(engine *sandbox.Engine) *Service {
	s.docker = engine
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
	return &Service{cfg: cfg.withDefaults(), store: st, engine: engine, agents: newAgentHub()}
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
	case protocol.OpWorkspaceFinalize:
		return s.finalize(ctx, req)
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
	case protocol.OpSkillsRun:
		return s.skillsRun(ctx, req)
	case protocol.OpSkillSuggest:
		return s.skillSuggest(req)
	case protocol.OpAgentSpawn, protocol.OpAgentStatus, protocol.OpAgentLogs, protocol.OpAgentMessage, protocol.OpAgentCancel, protocol.OpAgentList:
		return s.agentDispatch(req)
	case protocol.OpFilesList, protocol.OpFilesRead, protocol.OpFilesWrite, protocol.OpFilesWriteBatch, protocol.OpFilesApplyPatch, protocol.OpFilesDelete, protocol.OpFilesMove, protocol.OpFilesMkdir, protocol.OpGrepSearch, protocol.OpSymbolsSearch, protocol.OpSymbolsReferences, protocol.OpExecRun, protocol.OpGitStatus, protocol.OpGitDiff, protocol.OpGitLog, protocol.OpGitBranch, protocol.OpGitCheckout, protocol.OpGitAdd, protocol.OpGitCommit, protocol.OpGitMerge, protocol.OpGitRebase, protocol.OpWorktreesList, protocol.OpWorktreesCreate, protocol.OpWorktreesRemove, protocol.OpSkillsList, protocol.OpSkillsRead, protocol.OpHooksList, protocol.OpHooksRun, protocol.OpDeploymentsList, protocol.OpDeploymentsRun, protocol.OpSessionsList, protocol.OpSessionsOpen, protocol.OpSessionsIO, protocol.OpSessionsClose, protocol.OpShellOpen, protocol.OpShellIO, protocol.OpShellClose, protocol.OpTasksList, protocol.OpTasksRun, protocol.OpTasksStatus, protocol.OpTasksCancel, protocol.OpTasksGraph, protocol.OpOperationStatus, protocol.OpOperationCancel, protocol.OpOperationWait:
		return s.runWorker(ctx, req)
	case protocol.OpSecretsList:
		return s.secretsList(req)
	case protocol.OpArtifactsList:
		return s.artifactsList(req)
	case protocol.OpArtifactsRead:
		return s.artifactsRead(req)
	case protocol.OpArtifactsDelete:
		return s.artifactsDelete(req)
	case protocol.OpArtifactsSnapshot:
		return s.artifactsSnapshot(req)
	case protocol.OpArtifactsRestore:
		return s.artifactsRestore(ctx, req)
	case protocol.OpMemoriesList:
		return s.memoriesList(req)
	case protocol.OpMemoriesRead:
		return s.memoriesRead(req)
	case protocol.OpMemoriesWrite:
		return s.memoriesWrite(req)
	case protocol.OpMemoriesSearch:
		return s.memoriesSearch(req)
	case protocol.OpMemoriesDelete:
		return s.memoriesDelete(req)
	case protocol.OpKnowledgeCreate:
		return s.knowledgeCreate(req)
	case protocol.OpKnowledgeRead:
		return s.knowledgeRead(req)
	case protocol.OpKnowledgeUpdate:
		return s.knowledgeUpdate(req)
	case protocol.OpKnowledgeDelete:
		return s.knowledgeDelete(req)
	case protocol.OpKnowledgeList:
		return s.knowledgeList(req)
	case protocol.OpKnowledgeSearch:
		return s.knowledgeSearch(req)
	case protocol.OpKnowledgeLink:
		return s.knowledgeLink(req)
	case protocol.OpKnowledgeUnlink:
		return s.knowledgeUnlink(req)
	case protocol.OpKnowledgeGraph:
		return s.knowledgeGraph(req)
	case protocol.OpHooksActivate:
		return s.hooksActivate(req)
	case protocol.OpHooksDeactivate:
		return s.hooksDeactivate(req)
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
		EnvironmentID:  input.EnvironmentID,
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

func (s *Service) skillsRun(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	if s.grants == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "privilege grant storage is not configured", true)
	}
	var input struct {
		WorkspaceID           string `json:"workspaceId"`
		Name                  string `json:"name"`
		Script                string `json:"script"`
		ExpectedSHA256        string `json:"expectedSha256"`
		ExpectedContentSHA256 string `json:"expectedContentSha256"`
		ApprovalGrantToken    string `json:"approvalGrantToken"`
	}
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skills_run input", false)
		}
	}
	expected := input.ExpectedContentSHA256
	if expected == "" {
		expected = input.ExpectedSHA256
	}
	if expected == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "expectedContentSha256 or expectedSha256 is required to run a skill", false)
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	rec, errRes := s.resolveWorkspace(ownerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	command := grants.SkillGrantCommand(input.Name, input.Script, expected)
	if input.ApprovalGrantToken == "" {
		grant, err := s.grants.Create(ownerID, rec.ID, command, ".", 60_000)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, "privilege grant store is unavailable", true)
		}
		return grants.ApprovalRequired(grant, input.Name, input.Script)
	}
	digest := grants.SkillGrantDigest(input.Name, input.Script, expected)
	if !s.grants.Consume(ownerID, rec.ID, input.ApprovalGrantToken, digest, ".") {
		return protocol.Fail(protocol.ErrorForbidden, "Invalid, expired, or already-consumed approval grant token", false)
	}
	if fail := s.requireActiveExecutor(rec); fail != nil {
		return *fail
	}
	return s.runSkillHelper(ctx, rec, req.Input)
}

func (s *Service) runSkillHelper(ctx context.Context, rec store.Record, input json.RawMessage) protocol.ToolResult {
	if s.docker == nil {
		return protocol.Fail(protocol.ErrorUnavailable, "skill helper container is not configured", true)
	}
	fields := map[string]any{}
	if len(input) > 0 {
		if err := json.Unmarshal(input, &fields); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skills_run input", false)
		}
	}
	delete(fields, "approvalGrantToken")
	timeout := 60 * time.Second
	if raw, ok := fields["timeoutMs"]; ok {
		switch v := raw.(type) {
		case float64:
			if v > 0 {
				timeout = time.Duration(v) * time.Millisecond
			}
		}
	}
	payload, err := json.Marshal(map[string]any{"operation": protocol.OpSkillsRun, "input": fields})
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, "skill helper payload is invalid", true)
	}
	job := filepath.Join(s.cfg.JobsRoot, rec.ID)
	spec := sandbox.SkillHelperSpec{
		Name:           "chm-skill-" + rec.ID[3:minLen(rec.ID, 15)] + "-" + fmt.Sprintf("%x", time.Now().UnixNano()&0xffffffff),
		Image:          s.cfg.ExecutorImage,
		InstanceID:     s.cfg.InstanceID,
		WorkspaceID:    rec.ID,
		RepositoryPath: filepath.Join(job, "repo"),
		ToolsPath:      filepath.Join(job, "tools"),
		CachePath:      filepath.Join(job, "cache"),
		Network:        rec.NetworkProfile,
	}
	args := sandbox.SkillHelperArgs(spec)
	if err := sandbox.ValidateSkillHelperArgs(args); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := s.docker.Invoke(runCtx, args, string(payload))
	if err != nil {
		return failFrom(err)
	}
	raw := strings.TrimSpace(res.Stdout)
	if raw == "" {
		raw = strings.TrimSpace(res.Stderr)
	}
	var got protocol.ToolResult
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		return protocol.Fail(protocol.ErrorInternal, "skill helper container returned an invalid bounded result", true)
	}
	data, _ := got.Data.(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	data["executionMode"] = "helper-container"
	got.Data = data
	if res.Truncated {
		got.Truncated = true
	}
	return got
}

const typesafeEgressCeiling = 8192

func (s *Service) skillSuggest(req protocol.RunnerRequest) protocol.ToolResult {
	var input struct {
		Prompt      string `json:"prompt"`
		WorkspaceID string `json:"workspaceId"`
	}
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid skill_suggest input", false)
		}
	}
	if strings.TrimSpace(input.Prompt) == "" {
		return protocol.Fail(protocol.ErrorInvalidInput, "prompt is required", false)
	}
	if len([]byte(input.Prompt)) > typesafeEgressCeiling {
		return protocol.Fail(protocol.ErrorInvalidInput, "the prompt exceeds the egress byte bound", false)
	}
	reason := "not_configured"
	if input.WorkspaceID == "" {
		reason = "empty_roster"
	} else if rec, errRes := s.resolveWorkspace(req.OwnerID, input.WorkspaceID); errRes != nil {
		return *errRes
	} else if rec.Status != store.StatusActive {
		reason = "empty_roster"
	} else {
		reason = "not_configured"
	}
	return protocol.Success("No suggestion", map[string]any{
		"suggested":      nil,
		"reason":         reason,
		"cached":         false,
		"latencyMs":      0,
		"outboundCalls":  0,
		"redactionCount": 0,
	})
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
	if s.docker != nil && rec.ContainerName == "" {
		fail := protocol.Fail(protocol.ErrorUnavailable, "workspace executor is unavailable", true)
		return &fail
	}
	return nil
}

func (s *Service) executeInJob(ctx context.Context, rec store.Record, op protocol.Operation, input json.RawMessage) protocol.ToolResult {
	if s.docker != nil {
		return s.execInContainer(ctx, rec, op, input)
	}
	root := filepath.Join(s.cfg.JobsRoot, rec.ID, "repo")
	return (executor.Workspace{Root: root}).Execute(ctx, op, input)
}

func (s *Service) execInContainer(ctx context.Context, rec store.Record, op protocol.Operation, input json.RawMessage) protocol.ToolResult {
	if rec.ContainerName == "" {
		return protocol.Fail(protocol.ErrorUnavailable, "workspace executor is unavailable", true)
	}
	operationID := protocol.NewOpaqueID(protocol.PrefixOperation)
	timeout := 65 * time.Second
	if len(input) > 0 {
		var fields struct {
			TimeoutMs   int    `json:"timeoutMs"`
			OperationID string `json:"operationId"`
		}
		if err := json.Unmarshal(input, &fields); err == nil {
			if fields.TimeoutMs > 0 {
				timeout = time.Duration(fields.TimeoutMs+5_000) * time.Millisecond
			}
			if protocol.ValidOpaqueID(protocol.PrefixOperation, fields.OperationID) {
				operationID = fields.OperationID
			}
		}
	}
	var parsed any
	if len(input) == 0 {
		parsed = map[string]any{}
	} else if err := json.Unmarshal(input, &parsed); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid worker input", false)
	}
	payload, err := json.Marshal(map[string]any{"operation": op, "input": parsed})
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, "worker payload is invalid", true)
	}
	args := sandbox.WorkerExecArgs(rec.ContainerName, operationID)
	if err := sandbox.ValidateWorkerExecArgs(args); err != nil {
		return protocol.Fail(protocol.ErrorInternal, err.Error(), false)
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := s.docker.Invoke(runCtx, args, string(payload))
	if err != nil {
		return failFrom(err)
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		if msg == "" {
			msg = "worker failed"
		}
		return protocol.Fail(protocol.ErrorInternal, "worker failed: "+msg, true)
	}
	raw := strings.TrimSpace(res.Stdout)
	var got protocol.ToolResult
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		return protocol.Fail(protocol.ErrorInternal, "worker returned an invalid bounded result", true)
	}
	if data, ok := got.Data.(map[string]any); ok {
		data["operationId"] = operationID
		got.Data = data
	}
	if res.Truncated {
		got.Truncated = true
	}
	return got
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

func artifactFail(err error) protocol.ToolResult {
	if art, ok := err.(*artifacts.Error); ok {
		return protocol.Fail(art.Code, art.Message, false)
	}
	return protocol.Fail(protocol.ErrorInternal, "artifact store is unavailable", true)
}

func (s *Service) requireArtifacts() (*artifacts.Store, *protocol.ToolResult) {
	if s.artifacts == nil {
		fail := protocol.Fail(protocol.ErrorUnavailable, "artifact storage is not configured", true)
		return nil, &fail
	}
	return s.artifacts, nil
}

func (s *Service) artifactsList(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireArtifacts()
	if fail != nil {
		return *fail
	}
	var input struct {
		Cursor string `json:"cursor"`
		Limit  int    `json:"limit"`
	}
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid artifacts_list input", false)
		}
	}
	limit := input.Limit
	if limit == 0 {
		limit = 50
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	page, err := store.List(ownerID, limit, input.Cursor, time.Time{})
	if err != nil {
		return artifactFail(err)
	}
	items := make([]map[string]any, 0, len(page.Artifacts))
	for _, item := range page.Artifacts {
		items = append(items, item.PublicJSON())
	}
	data := map[string]any{"artifacts": items}
	got := protocol.Success("Artifacts listed", data)
	if page.Cursor != "" {
		got.Cursor = page.Cursor
		data["cursor"] = page.Cursor
		got.Data = data
	}
	return got
}

func (s *Service) artifactsRead(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireArtifacts()
	if fail != nil {
		return *fail
	}
	var input struct {
		ArtifactID string `json:"artifactId"`
		Offset     int    `json:"offset"`
		Limit      int    `json:"limit"`
	}
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixArtifact, input.ArtifactID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid artifact identifier", false)
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	chunk, err := store.Read(ownerID, input.ArtifactID, input.Offset, input.Limit, time.Time{})
	if err != nil {
		return artifactFail(err)
	}
	data := map[string]any{
		"artifactId":    chunk.ArtifactID,
		"logicalName":   chunk.LogicalName,
		"offset":        chunk.Offset,
		"bytesReturned": chunk.BytesReturned,
		"totalBytes":    chunk.TotalBytes,
		"sha256":        chunk.SHA256,
		"eof":           chunk.EOF,
		"content":       chunk.Content,
	}
	got := protocol.Success("Artifact chunk read", data)
	if !chunk.EOF {
		got.Truncated = true
		got.Cursor = strconv.Itoa(chunk.Offset + chunk.BytesReturned)
	}
	return got
}

func (s *Service) artifactsDelete(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireArtifacts()
	if fail != nil {
		return *fail
	}
	var input struct {
		ArtifactID         string `json:"artifactId"`
		ExpectedGeneration int    `json:"expectedGeneration"`
	}
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixArtifact, input.ArtifactID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid artifact identifier", false)
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	deleted, err := store.Delete(ownerID, input.ArtifactID, input.ExpectedGeneration)
	if err != nil {
		return artifactFail(err)
	}
	return protocol.Success("Artifact deleted", deleted.PublicJSON())
}

func (s *Service) artifactsSnapshot(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireArtifacts()
	if fail != nil {
		return *fail
	}
	var input struct {
		WorkspaceID      string `json:"workspaceId"`
		Path             string `json:"path"`
		LogicalName      string `json:"logicalName"`
		RetentionSeconds int    `json:"retentionSeconds"`
	}
	if err := json.Unmarshal(req.Input, &input); err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid artifacts_snapshot input", false)
	}
	rec, errRes := s.resolveWorkspace(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	if fail := s.requireActiveExecutor(rec); fail != nil {
		return *fail
	}
	root := filepath.Join(s.cfg.JobsRoot, rec.ID, "repo")
	target, err := executor.SafePath(root, input.Path, false)
	if err != nil {
		return protocol.Fail(protocol.ErrorInvalidInput, err.Error(), false)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		return protocol.Fail(protocol.ErrorNotFound, "workspace file not found", false)
	}
	var retentionMs int64
	if input.RetentionSeconds > 0 {
		retentionMs = int64(input.RetentionSeconds) * 1000
	}
	created, err := store.Create(rec.OwnerID, input.LogicalName, content, rec.ID, "", rec.EnvironmentID, retentionMs, time.Time{})
	if err != nil {
		return artifactFail(err)
	}
	return protocol.Success("Artifact snapshot created", created.PublicJSON())
}

func (s *Service) artifactsRestore(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireArtifacts()
	if fail != nil {
		return *fail
	}
	var input struct {
		WorkspaceID    string `json:"workspaceId"`
		ArtifactID     string `json:"artifactId"`
		Path           string `json:"path"`
		Overwrite      bool   `json:"overwrite"`
		ExpectedSHA256 string `json:"expectedSha256"`
	}
	if err := json.Unmarshal(req.Input, &input); err != nil || !protocol.ValidOpaqueID(protocol.PrefixArtifact, input.ArtifactID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "invalid artifact identifier", false)
	}
	rec, errRes := s.resolveWorkspace(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	if fail := s.requireActiveExecutor(rec); fail != nil {
		return *fail
	}
	payload, err := store.ReadPayload(rec.OwnerID, input.ArtifactID, time.Time{})
	if err != nil {
		return artifactFail(err)
	}
	if input.ExpectedSHA256 != "" && payload.Metadata.SHA256 != input.ExpectedSHA256 {
		return protocol.Fail(protocol.ErrorConflict, "artifact hash mismatch", false)
	}
	workerInput, err := json.Marshal(map[string]any{
		"path":           input.Path,
		"contentBase64":  base64.StdEncoding.EncodeToString(payload.Content),
		"overwrite":      input.Overwrite,
		"expectedSha256": input.ExpectedSHA256,
	})
	if err != nil {
		return protocol.Fail(protocol.ErrorInternal, "could not encode restore input", false)
	}
	got := s.executeInJob(ctx, rec, protocol.OpArtifactsRestore, workerInput)
	if !got.OK {
		return got
	}
	path := input.Path
	size := payload.Metadata.SizeBytes
	sha := payload.Metadata.SHA256
	if extra, ok := got.Data.(map[string]any); ok {
		if p, ok := extra["path"].(string); ok && p != "" {
			path = p
		}
		if n, ok := extra["sizeBytes"].(int); ok {
			size = n
		}
		if n, ok := extra["sizeBytes"].(float64); ok {
			size = int(n)
		}
		if h, ok := extra["sha256"].(string); ok && h != "" {
			sha = h
		}
	}
	return protocol.Success("Artifact restored to workspace", map[string]any{
		"artifactId":  payload.Metadata.ArtifactID,
		"workspaceId": rec.ID,
		"path":        path,
		"sizeBytes":   size,
		"sha256":      sha,
	})
}

type memoryInput struct {
	WorkspaceID        string   `json:"workspaceId"`
	Scope              string   `json:"scope"`
	Name               string   `json:"name"`
	MemoryID           string   `json:"memoryId"`
	Content            string   `json:"content"`
	Tags               []string `json:"tags"`
	Query              string   `json:"query"`
	TagMatch           string   `json:"tagMatch"`
	Cursor             string   `json:"cursor"`
	Limit              *int     `json:"limit"`
	RetentionSeconds   int      `json:"retentionSeconds"`
	ExpectedGeneration *int     `json:"expectedGeneration"`
}

func memoryFail(err error) protocol.ToolResult {
	if mem, ok := err.(*memories.Error); ok {
		return protocol.Fail(mem.Code, mem.Message, false)
	}
	return protocol.Fail(protocol.ErrorInternal, "memory store is unavailable", true)
}

func (s *Service) requireMemories() (*memories.Store, *protocol.ToolResult) {
	if s.memories == nil {
		fail := protocol.Fail(protocol.ErrorUnavailable, "memory storage is not configured", true)
		return nil, &fail
	}
	return s.memories, nil
}

func repositoryKey(url string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(url)))
	return hex.EncodeToString(sum[:])
}

func (s *Service) memoryContext(req protocol.RunnerRequest, input memoryInput) (ownerID string, rec store.Record, errRes *protocol.ToolResult) {
	ownerID = req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	rec, errRes = s.resolveWorkspace(ownerID, input.WorkspaceID)
	if errRes != nil {
		return "", store.Record{}, errRes
	}
	return ownerID, rec, nil
}

func (s *Service) memoriesWrite(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireMemories()
	if fail != nil {
		return *fail
	}
	var input memoryInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid memories_write input", false)
		}
	}
	ownerID, rec, errRes := s.memoryContext(req, input)
	if errRes != nil {
		return *errRes
	}
	expected := 0
	if input.ExpectedGeneration != nil {
		expected = *input.ExpectedGeneration
	}
	row, err := store.Write(memories.WriteParams{
		PrincipalID:        ownerID,
		Scope:              input.Scope,
		RepositoryKey:      repositoryKey(rec.RepositoryURL),
		WorkspaceID:        rec.ID,
		Name:               input.Name,
		Content:            input.Content,
		Tags:               input.Tags,
		RetentionSeconds:   input.RetentionSeconds,
		ExpectedGeneration: expected,
	})
	if err != nil {
		return memoryFail(err)
	}
	return protocol.Success("Memory note saved", row.PublicJSON())
}

func (s *Service) memoriesRead(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireMemories()
	if fail != nil {
		return *fail
	}
	var input memoryInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid memories_read input", false)
		}
	}
	ownerID, rec, errRes := s.memoryContext(req, input)
	if errRes != nil {
		return *errRes
	}
	row, err := store.Read(memories.Lookup{
		PrincipalID: ownerID, ID: input.MemoryID, Name: input.Name, Scope: input.Scope,
		RepositoryKey: repositoryKey(rec.RepositoryURL), WorkspaceID: rec.ID,
	})
	if err != nil {
		return memoryFail(err)
	}
	return protocol.Success("Memory note read", row.PublicJSON())
}

func (s *Service) memoriesList(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireMemories()
	if fail != nil {
		return *fail
	}
	var input memoryInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid memories_list input", false)
		}
	}
	ownerID, rec, errRes := s.memoryContext(req, input)
	if errRes != nil {
		return *errRes
	}
	limit := 50
	if input.Limit != nil {
		limit = *input.Limit
	}
	rows, next, err := store.List(memories.ListParams{
		PrincipalID: ownerID, Scope: input.Scope, RepositoryKey: repositoryKey(rec.RepositoryURL),
		WorkspaceID: rec.ID, Tags: input.Tags, TagMatch: input.TagMatch, Limit: limit, Cursor: input.Cursor,
	})
	if err != nil {
		return memoryFail(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ListJSON())
	}
	got := protocol.Success(fmt.Sprintf("Found %d memories", len(out)), map[string]any{"memories": out})
	if next != "" {
		got.Cursor = next
		got.Truncated = true
		got.Data = map[string]any{"memories": out, "cursor": next}
	}
	return got
}

func (s *Service) memoriesSearch(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireMemories()
	if fail != nil {
		return *fail
	}
	var input memoryInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid memories_search input", false)
		}
	}
	ownerID, rec, errRes := s.memoryContext(req, input)
	if errRes != nil {
		return *errRes
	}
	limit := 20
	if input.Limit != nil {
		limit = *input.Limit
	}
	rows, next, err := store.Search(memories.ListParams{
		PrincipalID: ownerID, Scope: input.Scope, RepositoryKey: repositoryKey(rec.RepositoryURL),
		WorkspaceID: rec.ID, Tags: input.Tags, TagMatch: input.TagMatch, Query: input.Query, Limit: limit, Cursor: input.Cursor,
	})
	if err != nil {
		return memoryFail(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.PublicJSON())
	}
	got := protocol.Success(fmt.Sprintf("Found %d matching memories", len(out)), map[string]any{"memories": out})
	if next != "" {
		got.Cursor = next
		got.Truncated = true
		got.Data = map[string]any{"memories": out, "cursor": next}
	}
	return got
}

func (s *Service) memoriesDelete(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireMemories()
	if fail != nil {
		return *fail
	}
	var input memoryInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid memories_delete input", false)
		}
	}
	ownerID, rec, errRes := s.memoryContext(req, input)
	if errRes != nil {
		return *errRes
	}
	expected := 1
	if input.ExpectedGeneration != nil {
		expected = *input.ExpectedGeneration
	}
	if err := store.Delete(memories.Lookup{
		PrincipalID: ownerID, ID: input.MemoryID, Name: input.Name, Scope: input.Scope,
		RepositoryKey: repositoryKey(rec.RepositoryURL), WorkspaceID: rec.ID,
	}, expected); err != nil {
		return memoryFail(err)
	}
	return protocol.Success("Memory note deleted", map[string]any{"deleted": true})
}

type knowledgeInput struct {
	WorkspaceID        string   `json:"workspaceId"`
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Scope              string   `json:"scope"`
	ProjectID          string   `json:"projectId"`
	Title              string   `json:"title"`
	Content            string   `json:"content"`
	JournalType        string   `json:"journalType"`
	OccurredAt         *int64   `json:"occurredAt"`
	Tags               []string `json:"tags"`
	Kinds              []string `json:"kinds"`
	TagMatch           string   `json:"tagMatch"`
	Query              string   `json:"query"`
	Cursor             string   `json:"cursor"`
	Limit              *int     `json:"limit"`
	RetentionSeconds   *int     `json:"retentionSeconds"`
	ExpectedGeneration *int     `json:"expectedGeneration"`
	SourceID           string   `json:"sourceId"`
	TargetID           string   `json:"targetId"`
	LinkID             string   `json:"linkId"`
	Relation           string   `json:"relation"`
	RootID             string   `json:"rootId"`
	Depth              *int     `json:"depth"`
	MaxNodes           *int     `json:"maxNodes"`
}

func knowledgeFail(err error) protocol.ToolResult {
	if kn, ok := err.(*knowledge.Error); ok {
		return protocol.Fail(kn.Code, kn.Message, false)
	}
	return protocol.Fail(protocol.ErrorInternal, "knowledge store is unavailable", true)
}

func (s *Service) requireKnowledge() (*knowledge.Store, *protocol.ToolResult) {
	if s.knowledge == nil {
		fail := protocol.Fail(protocol.ErrorUnavailable, "knowledge storage is not configured", true)
		return nil, &fail
	}
	return s.knowledge, nil
}

func (s *Service) knowledgeContext(req protocol.RunnerRequest, input knowledgeInput) (ownerID string, rec store.Record, errRes *protocol.ToolResult) {
	ownerID = req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	rec, errRes = s.resolveWorkspace(ownerID, input.WorkspaceID)
	if errRes != nil {
		return "", store.Record{}, errRes
	}
	return ownerID, rec, nil
}

func (s *Service) knowledgeCreate(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_create input", false)
		}
	}
	ownerID, rec, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	expected := 0
	if input.ExpectedGeneration != nil {
		expected = *input.ExpectedGeneration
	}
	retention := 0
	if input.RetentionSeconds != nil {
		retention = *input.RetentionSeconds
	}
	occurred := int64(0)
	if input.OccurredAt != nil {
		occurred = *input.OccurredAt
	}
	item, err := store.Create(knowledge.CreateParams{
		PrincipalID: ownerID, Kind: input.Kind, Scope: input.Scope, ProjectID: input.ProjectID,
		WorkspaceID: rec.ID, Title: input.Title, Content: input.Content, JournalType: input.JournalType,
		OccurredAt: occurred, Tags: input.Tags, RetentionSeconds: retention, ExpectedGeneration: expected,
	})
	if err != nil {
		return knowledgeFail(err)
	}
	return protocol.Success("Knowledge item created", item.PublicJSON())
}

func (s *Service) knowledgeRead(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_read input", false)
		}
	}
	ownerID, _, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	item, err := store.Read(ownerID, input.ID)
	if err != nil {
		return knowledgeFail(err)
	}
	return protocol.Success("Knowledge item read", item.PublicJSON())
}

func (s *Service) knowledgeUpdate(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var raw map[string]any
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &raw); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_update input", false)
		}
	}
	var input knowledgeInput
	_ = json.Unmarshal(req.Input, &input)
	ownerID, _, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	expected := 0
	if input.ExpectedGeneration != nil {
		expected = *input.ExpectedGeneration
	}
	p := knowledge.UpdateParams{PrincipalID: ownerID, ID: input.ID, ExpectedGeneration: expected}
	if _, ok := raw["title"]; ok {
		p.Title = &input.Title
	}
	if _, ok := raw["content"]; ok {
		p.Content = &input.Content
	}
	if _, ok := raw["journalType"]; ok {
		p.JournalType = &input.JournalType
	}
	if input.OccurredAt != nil {
		p.OccurredAt = input.OccurredAt
	}
	if _, ok := raw["tags"]; ok {
		p.Tags = &input.Tags
	}
	p.RetentionSeconds = input.RetentionSeconds
	item, err := store.Update(p)
	if err != nil {
		return knowledgeFail(err)
	}
	return protocol.Success("Knowledge item updated", item.PublicJSON())
}

func (s *Service) knowledgeDelete(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_delete input", false)
		}
	}
	ownerID, _, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	expected := 0
	if input.ExpectedGeneration != nil {
		expected = *input.ExpectedGeneration
	}
	if err := store.Delete(ownerID, input.ID, expected); err != nil {
		return knowledgeFail(err)
	}
	return protocol.Success("Knowledge item deleted", map[string]any{"deleted": true})
}

func (s *Service) knowledgeList(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_list input", false)
		}
	}
	ownerID, rec, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	limit := 50
	if input.Limit != nil {
		limit = *input.Limit
	}
	rows, next, err := store.List(knowledge.ListParams{
		PrincipalID: ownerID, Kind: input.Kind, Scope: input.Scope, ProjectID: input.ProjectID,
		WorkspaceID: rec.ID, JournalType: input.JournalType, Tags: input.Tags, TagMatch: input.TagMatch,
		Limit: limit, Cursor: input.Cursor,
	})
	if err != nil {
		return knowledgeFail(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.PublicJSON())
	}
	got := protocol.Success(fmt.Sprintf("Found %d knowledge items", len(out)), map[string]any{"items": out})
	if next != "" {
		got.Cursor = next
		got.Truncated = true
		got.Data = map[string]any{"items": out, "cursor": next}
	}
	return got
}

func (s *Service) knowledgeSearch(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_search input", false)
		}
	}
	ownerID, rec, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	limit := 20
	if input.Limit != nil {
		limit = *input.Limit
	}
	rows, next, err := store.Search(knowledge.ListParams{
		PrincipalID: ownerID, Kind: input.Kind, Scope: input.Scope, ProjectID: input.ProjectID,
		WorkspaceID: rec.ID, JournalType: input.JournalType, Tags: input.Tags, TagMatch: input.TagMatch,
		Query: input.Query, Kinds: input.Kinds, Limit: limit, Cursor: input.Cursor,
	})
	if err != nil {
		return knowledgeFail(err)
	}
	results := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		results = append(results, map[string]any{"item": row.PublicJSON(), "relevancePercent": 100, "matchMode": "lexical"})
	}
	got := protocol.Success(fmt.Sprintf("Found %d matching knowledge items", len(results)), map[string]any{"results": results})
	if next != "" {
		got.Cursor = next
		got.Truncated = true
		got.Data = map[string]any{"results": results, "cursor": next}
	}
	return got
}

func (s *Service) knowledgeLink(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_link input", false)
		}
	}
	ownerID, _, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	link, err := store.CreateLink(ownerID, input.SourceID, input.TargetID, input.Relation, "manual")
	if err != nil {
		return knowledgeFail(err)
	}
	return protocol.Success("Knowledge link created", link.PublicJSON())
}

func (s *Service) knowledgeUnlink(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_unlink input", false)
		}
	}
	ownerID, _, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	unlinked, err := store.DeleteLink(ownerID, input.LinkID, input.SourceID, input.TargetID, input.Relation)
	if err != nil {
		return knowledgeFail(err)
	}
	return protocol.Success("Knowledge link removed", map[string]any{"unlinked": unlinked})
}

func (s *Service) knowledgeGraph(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireKnowledge()
	if fail != nil {
		return *fail
	}
	var input knowledgeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid knowledge_graph input", false)
		}
	}
	ownerID, _, errRes := s.knowledgeContext(req, input)
	if errRes != nil {
		return *errRes
	}
	depth := 1
	if input.Depth != nil {
		depth = *input.Depth
	}
	maxNodes := 50
	if input.MaxNodes != nil {
		maxNodes = *input.MaxNodes
	}
	nodes, edges, truncated, err := store.Graph(knowledge.GraphParams{
		PrincipalID: ownerID, RootID: input.RootID, Depth: depth, MaxNodes: maxNodes,
		Kinds: input.Kinds, ProjectID: input.ProjectID,
	})
	if err != nil {
		return knowledgeFail(err)
	}
	outNodes := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		outNodes = append(outNodes, n.PublicJSON())
	}
	outEdges := make([]map[string]any, 0, len(edges))
	for _, e := range edges {
		outEdges = append(outEdges, e.PublicJSON())
	}
	got := protocol.Success(fmt.Sprintf("Graph returned with %d nodes and %d edges", len(outNodes), len(outEdges)), map[string]any{
		"nodes": outNodes, "edges": outEdges, "truncated": truncated,
	})
	got.Truncated = truncated
	return got
}

type hooksActivateInput struct {
	WorkspaceID      string   `json:"workspaceId"`
	ManifestSHA256   string   `json:"manifestSha256"`
	Events           []string `json:"events"`
	RetentionSeconds *int     `json:"retentionSeconds"`
}

func hooksFail(err error) protocol.ToolResult {
	if he, ok := err.(*hooks.Error); ok {
		return protocol.Fail(he.Code, he.Message, false)
	}
	return protocol.Fail(protocol.ErrorInternal, "hook activation store is unavailable", true)
}

func (s *Service) requireHooks() (*hooks.Store, *protocol.ToolResult) {
	if s.hooks == nil {
		fail := protocol.Fail(protocol.ErrorUnavailable, "hook activation storage is not configured", true)
		return nil, &fail
	}
	return s.hooks, nil
}

func (s *Service) hooksActivate(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireHooks()
	if fail != nil {
		return *fail
	}
	var input hooksActivateInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid hooks_activate input", false)
		}
	}
	if len(input.Events) < 1 || len(input.Events) > 10 {
		return protocol.Fail(protocol.ErrorInvalidInput, "events must contain between 1 and 10 hook events", false)
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	rec, errRes := s.resolveWorkspace(ownerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	retention := 0
	if input.RetentionSeconds != nil {
		retention = *input.RetentionSeconds
	}
	activations := make([]map[string]any, 0, len(input.Events))
	for _, event := range input.Events {
		act, err := store.Activate(ownerID, rec.ID, event, input.ManifestSHA256, retention)
		if err != nil {
			return hooksFail(err)
		}
		activations = append(activations, act.PublicJSON())
	}
	return protocol.Success("Hooks activated", map[string]any{"activations": activations})
}

func (s *Service) hooksDeactivate(req protocol.RunnerRequest) protocol.ToolResult {
	store, fail := s.requireHooks()
	if fail != nil {
		return *fail
	}
	var input hooksActivateInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid hooks_deactivate input", false)
		}
	}
	if len(input.Events) > 10 {
		return protocol.Fail(protocol.ErrorInvalidInput, "events must contain at most 10 hook events", false)
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	rec, errRes := s.resolveWorkspace(ownerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	if len(input.Events) == 0 {
		if _, err := store.Deactivate(ownerID, rec.ID, ""); err != nil {
			return hooksFail(err)
		}
	} else {
		for _, event := range input.Events {
			if _, err := store.Deactivate(ownerID, rec.ID, event); err != nil {
				return hooksFail(err)
			}
		}
	}
	return protocol.Success("Hooks deactivated", map[string]any{"deactivated": true})
}

const globalSecretEnvironment = "global"

type secretsListInput struct {
	WorkspaceID   string `json:"workspaceId"`
	EnvironmentID string `json:"environmentId"`
	Query         string `json:"query"`
	Cursor        string `json:"cursor"`
	Limit         int    `json:"limit"`
}

func (s *Service) secretsList(req protocol.RunnerRequest) protocol.ToolResult {
	var input secretsListInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid secrets_list input", false)
		}
	}
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "owner"
	}
	environmentID := input.EnvironmentID
	if input.WorkspaceID != "" {
		if !protocol.ValidOpaqueID(protocol.PrefixWorkspace, input.WorkspaceID) {
			return protocol.Fail(protocol.ErrorInvalidInput, "workspaceId is required", false)
		}
		rec, errRes := s.requireOwned(ownerID, input.WorkspaceID)
		if errRes != nil {
			return *errRes
		}
		if environmentID == "" {
			environmentID = rec.EnvironmentID
		}
	}
	if environmentID == "" {
		seen := map[string]struct{}{}
		var unique []string
		for _, rec := range s.store.List(ownerID) {
			if rec.Status != store.StatusActive && rec.Status != store.StatusCreating {
				continue
			}
			if rec.EnvironmentID == "" {
				continue
			}
			if _, ok := seen[rec.EnvironmentID]; ok {
				continue
			}
			seen[rec.EnvironmentID] = struct{}{}
			unique = append(unique, rec.EnvironmentID)
		}
		if len(unique) == 1 {
			environmentID = unique[0]
		} else if len(unique) > 1 {
			return protocol.Fail(protocol.ErrorConflict, "multiple active workspaces exist with different environments; specify an explicit environmentId or workspaceId", false)
		}
	}
	if environmentID != "" && environmentID != globalSecretEnvironment && !protocol.ValidOpaqueID(protocol.PrefixEnvironment, environmentID) {
		return protocol.Fail(protocol.ErrorInvalidInput, "environmentId is invalid", false)
	}
	offset := 0
	if input.Cursor != "" {
		n, err := strconv.Atoi(input.Cursor)
		if err != nil || n < 0 {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid secrets_list cursor", false)
		}
		offset = n
	}
	limit := input.Limit
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 500 {
		return protocol.Fail(protocol.ErrorInvalidInput, "limit must be between 1 and 500", false)
	}
	merged := map[string]map[string]any{}
	order := make([]string, 0)
	appendViews := func(views []secrets.View, scope string) {
		for _, view := range views {
			item := map[string]any{
				"name":          view.Name,
				"description":   nullableString(view.Description),
				"scope":         scope,
				"environmentId": view.EnvironmentID,
				"version":       view.Version,
				"updatedAt":     view.UpdatedAt.UTC().Format(time.RFC3339Nano),
			}
			if _, exists := merged[view.Name]; !exists {
				order = append(order, view.Name)
			}
			merged[view.Name] = item
		}
	}
	if s.secrets != nil {
		globals, err := s.secrets.List(ownerID, globalSecretEnvironment)
		if err != nil {
			return protocol.Fail(protocol.ErrorInternal, "secret metadata is unavailable", true)
		}
		appendViews(globals, "global")
		if environmentID != "" && environmentID != globalSecretEnvironment {
			envs, err := s.secrets.List(ownerID, environmentID)
			if err != nil {
				return protocol.Fail(protocol.ErrorInternal, "secret metadata is unavailable", true)
			}
			appendViews(envs, "environment")
		}
	}
	filtered := make([]map[string]any, 0, len(order))
	q := strings.ToLower(input.Query)
	for _, name := range order {
		item := merged[name]
		if q != "" {
			desc := ""
			if s, ok := item["description"].(string); ok {
				desc = s
			}
			if !strings.Contains(strings.ToLower(name), q) && !strings.Contains(strings.ToLower(desc), q) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	page := filtered[offset:end]
	hasMore := end < len(filtered)
	data := map[string]any{"secrets": page}
	got := protocol.Success(fmt.Sprintf("Listed %d secret reference(s)", len(page)), data)
	if hasMore {
		got.Cursor = strconv.Itoa(end)
		got.Truncated = true
		data["cursor"] = got.Cursor
		got.Data = data
	}
	return got
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
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
		"environmentId":    rec.EnvironmentID,
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

type finalizeInput struct {
	WorkspaceID    string   `json:"workspaceId"`
	Paths          []string `json:"paths"`
	All            *bool    `json:"all"`
	CommitMessage  string   `json:"commitMessage"`
	Branch         string   `json:"branch"`
	Push           *bool    `json:"push"`
	AuthorName     string   `json:"authorName"`
	AuthorEmail    string   `json:"authorEmail"`
	IdempotencyKey string   `json:"idempotencyKey"`
	Preflight      *struct {
		CheckDiff         *bool    `json:"checkDiff"`
		ForbiddenPatterns []string `json:"forbiddenPatterns"`
	} `json:"preflight"`
}

func (s *Service) finalize(ctx context.Context, req protocol.RunnerRequest) protocol.ToolResult {
	var input finalizeInput
	if len(req.Input) > 0 {
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return protocol.Fail(protocol.ErrorInvalidInput, "invalid workspace_finalize input", false)
		}
	}
	if strings.TrimSpace(input.CommitMessage) == "" || len(input.CommitMessage) > 10_000 {
		return protocol.Fail(protocol.ErrorInvalidInput, "commitMessage is required", false)
	}
	all := true
	if input.All != nil {
		all = *input.All
	}
	if !all && len(input.Paths) == 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "paths are required when all is false", false)
	}
	if all && len(input.Paths) > 0 {
		return protocol.Fail(protocol.ErrorInvalidInput, "paths must be empty when all is true", false)
	}
	if input.Branch != "" && !executorValidGitArg(input.Branch) {
		return protocol.Fail(protocol.ErrorInvalidInput, "branch cannot start with a dash", false)
	}
	rec, errRes := s.resolveWorkspace(req.OwnerID, input.WorkspaceID)
	if errRes != nil {
		return *errRes
	}
	if fail := s.requireActiveExecutor(rec); fail != nil {
		return *fail
	}
	checkDiff := true
	if input.Preflight != nil && input.Preflight.CheckDiff != nil {
		checkDiff = *input.Preflight.CheckDiff
	}
	if checkDiff {
		diff := s.executeInJob(ctx, rec, protocol.OpGitDiff, json.RawMessage(`{}`))
		if diff.Truncated {
			fail := protocol.Fail(protocol.ErrorLimitExceeded, "diff exceeds verification limit", false)
			fail.Data = map[string]any{"step": "preflight", "error": "diff output exceeds preflight capacity"}
			fail.Message = "Preflight check failed: diff output too large to verify cleanly"
			return fail
		}
		output := resultOutput(diff)
		if s.workingTreeHasConflictMarkers(rec) {
			fail := protocol.Fail(protocol.ErrorConflict, "Merge conflict markers detected", false)
			fail.Data = map[string]any{"step": "preflight", "errors": []string{"Merge conflict markers found in working tree"}}
			fail.Message = "Preflight check failed: unresolved merge conflict markers detected"
			return fail
		}
		if input.Preflight != nil {
			for _, pat := range input.Preflight.ForbiddenPatterns {
				if pat != "" && strings.Contains(output, pat) {
					fail := protocol.Fail(protocol.ErrorInvalidInput, fmt.Sprintf("Forbidden pattern %q detected", pat), false)
					fail.Data = map[string]any{"step": "preflight", "errors": []string{fmt.Sprintf("Forbidden pattern %q found in diff", pat)}}
					fail.Message = fmt.Sprintf("Preflight check failed: forbidden pattern %q detected", pat)
					return fail
				}
			}
		}
	}
	status := s.executeInJob(ctx, rec, protocol.OpGitStatus, json.RawMessage(`{}`))
	changed := false
	for _, line := range strings.Split(resultOutput(status), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "##") {
			changed = true
			break
		}
	}
	branch := input.Branch
	if branch == "" {
		branch = rec.Ref
	}
	if branch == "" {
		branch = "main"
	}
	pushWanted := true
	if input.Push != nil {
		pushWanted = *input.Push
	}
	if !changed {
		sha := headCommit(s.executeInJob(ctx, rec, protocol.OpGitLog, json.RawMessage(`{}`)))
		pushed := false
		if pushWanted {
			out, err := s.remotePush(ctx, rec, "HEAD:refs/heads/"+branch, "")
			if err != nil {
				fail := failFrom(err)
				fail.Message = "Working tree clean but push failed: " + fail.Message
				fail.Data = map[string]any{"step": "push", "commitSha": sha, "branch": branch, "pushed": false, "pushError": fail.Message, "resumeAction": "Call git_push or workspace_finalize to retry push"}
				if fail.Error != nil {
					fail.Error.ResumeAction = "Call git_push or workspace_finalize to retry push"
				}
				_ = out
				return fail
			}
			pushed = true
		}
		return protocol.Success(fmt.Sprintf("Workspace already clean and finalized at %s", shortSHA(sha)), map[string]any{
			"commitSha": sha, "branch": branch, "pushed": pushed, "alreadyFinalized": true, "finalStatus": status.Data,
		})
	}
	addInput, _ := json.Marshal(map[string]any{"all": all, "paths": input.Paths})
	staged := s.executeInJob(ctx, rec, protocol.OpGitAdd, addInput)
	if !staged.OK {
		fail := protocol.Fail(protocol.ErrorConflict, staged.Message, true)
		fail.Data = map[string]any{"step": "stage", "error": staged.Message}
		fail.Message = "Failed to stage changes"
		return fail
	}
	commitInput := s.withGitIdentity(req.OwnerID, mustJSON(map[string]any{
		"message": input.CommitMessage, "authorName": input.AuthorName, "authorEmail": input.AuthorEmail, "all": false,
	}))
	committed := s.executeInJob(ctx, rec, protocol.OpGitCommit, commitInput)
	if !committed.OK {
		fail := protocol.Fail(protocol.ErrorConflict, committed.Message, true)
		fail.Data = map[string]any{"step": "commit", "error": committed.Message}
		fail.Message = "Commit failed: " + committed.Message
		return fail
	}
	sha := headCommit(s.executeInJob(ctx, rec, protocol.OpGitLog, json.RawMessage(`{}`)))
	pushed := false
	var pushData any
	if pushWanted {
		out, err := s.remotePush(ctx, rec, "HEAD:refs/heads/"+branch, "")
		if err != nil {
			fail := failFrom(err)
			fail.Message = fmt.Sprintf("Commit created (%s) but push failed: %s", shortSHA(sha), fail.Message)
			fail.Data = map[string]any{"step": "push", "commitSha": sha, "branch": branch, "pushed": false, "pushError": fail.Message, "resumeAction": "Call git_push or workspace_finalize to retry push"}
			if fail.Error != nil {
				fail.Error.ResumeAction = "Call git_push or workspace_finalize to retry push"
			}
			_ = out
			return fail
		}
		pushed = true
		pushData = out
	}
	finalStatus := s.executeInJob(ctx, rec, protocol.OpGitStatus, json.RawMessage(`{}`))
	msg := fmt.Sprintf("Workspace finalized (commit %s)", shortSHA(sha))
	if pushed {
		msg = "Workspace finalized and pushed to " + branch
	}
	return protocol.Success(msg, map[string]any{
		"commitSha": sha, "branch": branch, "pushed": pushed, "pushResult": pushData, "finalStatus": finalStatus.Data,
	})
}

func markersIn(output string) bool {
	return strings.Contains(output, "<<<<<<< ") || strings.Contains(output, "=======\n") || strings.Contains(output, ">>>>>>> ")
}

func (s *Service) workingTreeHasConflictMarkers(rec store.Record) bool {
	root := filepath.Join(s.cfg.JobsRoot, rec.ID, "repo")
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1_048_576 {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if markersIn(string(raw)) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func resultOutput(got protocol.ToolResult) string {
	data, _ := got.Data.(map[string]any)
	out, _ := data["output"].(string)
	return out
}

func headCommit(got protocol.ToolResult) string {
	out := resultOutput(got)
	if out == "" {
		return ""
	}
	line := strings.SplitN(out, "\n", 2)[0]
	if tab := strings.IndexByte(line, '\t'); tab >= 0 {
		return strings.Fields(line[:tab])[0]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func executorValidGitArg(value string) bool {
	return value != "" && !strings.HasPrefix(value, "-") && !strings.Contains(value, "\x00") && len(value) <= 255
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
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
