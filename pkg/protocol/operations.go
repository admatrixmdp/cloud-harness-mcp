package protocol

// Operation is a public MCP / runner tool name from RunnerOperationSchema.
type Operation string

const (
	OpWorkspaceOpen         Operation = "workspace_open"
	OpWorkspaceList         Operation = "workspace_list"
	OpWorkspaceStatus       Operation = "workspace_status"
	OpWorkspaceCapabilities Operation = "workspace_capabilities"
	OpWorkspaceClose        Operation = "workspace_close"
	OpWorkspaceLeaseRenew   Operation = "workspace_lease_renew"
	OpWorkspaceRecover      Operation = "workspace_recover"
	OpWorkspaceContext      Operation = "workspace_context"
	OpWorkspaceSetActive    Operation = "workspace_set_active"
	OpWorkspaceFinalize     Operation = "workspace_finalize"

	OpFilesList         Operation = "files_list"
	OpFilesRead         Operation = "files_read"
	OpFilesWrite        Operation = "files_write"
	OpFilesWriteBatch   Operation = "files_write_batch"
	OpFilesApplyPatch   Operation = "files_apply_patch"
	OpFilesDelete       Operation = "files_delete"
	OpFilesMove         Operation = "files_move"
	OpFilesMkdir        Operation = "files_mkdir"
	OpGrepSearch        Operation = "grep_search"
	OpSymbolsSearch     Operation = "symbols_search"
	OpSymbolsReferences Operation = "symbols_references"

	OpExecRun    Operation = "exec_run"
	OpShellOpen  Operation = "shell_open"
	OpShellIO    Operation = "shell_io"
	OpShellClose Operation = "shell_close"

	OpSessionsList  Operation = "sessions_list"
	OpSessionsOpen  Operation = "sessions_open"
	OpSessionsIO    Operation = "sessions_io"
	OpSessionsClose Operation = "sessions_close"

	OpTasksList   Operation = "tasks_list"
	OpTasksRun    Operation = "tasks_run"
	OpTasksStatus Operation = "tasks_status"
	OpTasksCancel Operation = "tasks_cancel"
	OpTasksGraph  Operation = "tasks_graph"

	OpOperationStatus Operation = "operation_status"
	OpOperationCancel Operation = "operation_cancel"
	OpOperationWait   Operation = "operation_wait"

	OpGitStatus         Operation = "git_status"
	OpGitDiff           Operation = "git_diff"
	OpGitLog            Operation = "git_log"
	OpGitBranch         Operation = "git_branch"
	OpGitCheckout       Operation = "git_checkout"
	OpGitAdd            Operation = "git_add"
	OpGitCommit         Operation = "git_commit"
	OpGitFetch          Operation = "git_fetch"
	OpGitPull           Operation = "git_pull"
	OpGitPush           Operation = "git_push"
	OpGitMerge          Operation = "git_merge"
	OpGitRebase         Operation = "git_rebase"
	OpGitIdentityStatus Operation = "git_identity_status"
	OpGitIdentitySet    Operation = "git_identity_set"

	OpWorktreesList   Operation = "worktrees_list"
	OpWorktreesCreate Operation = "worktrees_create"
	OpWorktreesRemove Operation = "worktrees_remove"

	OpSkillsList   Operation = "skills_list"
	OpSkillsRead   Operation = "skills_read"
	OpSkillsRun    Operation = "skills_run"
	OpSkillSuggest Operation = "skill_suggest"

	OpHooksList       Operation = "hooks_list"
	OpHooksRun        Operation = "hooks_run"
	OpHooksActivate   Operation = "hooks_activate"
	OpHooksDeactivate Operation = "hooks_deactivate"

	OpMemoriesList   Operation = "memories_list"
	OpMemoriesRead   Operation = "memories_read"
	OpMemoriesWrite  Operation = "memories_write"
	OpMemoriesSearch Operation = "memories_search"
	OpMemoriesDelete Operation = "memories_delete"

	OpKnowledgeCreate Operation = "knowledge_create"
	OpKnowledgeRead   Operation = "knowledge_read"
	OpKnowledgeUpdate Operation = "knowledge_update"
	OpKnowledgeDelete Operation = "knowledge_delete"
	OpKnowledgeList   Operation = "knowledge_list"
	OpKnowledgeSearch Operation = "knowledge_search"
	OpKnowledgeLink   Operation = "knowledge_link"
	OpKnowledgeUnlink Operation = "knowledge_unlink"
	OpKnowledgeGraph  Operation = "knowledge_graph"

	OpDeploymentsList Operation = "deployments_list"
	OpDeploymentsRun  Operation = "deployments_run"

	OpArtifactsSnapshot Operation = "artifacts_snapshot"
	OpArtifactsList     Operation = "artifacts_list"
	OpArtifactsRead     Operation = "artifacts_read"
	OpArtifactsRestore  Operation = "artifacts_restore"
	OpArtifactsDelete   Operation = "artifacts_delete"

	OpGitHubAction Operation = "github_action"
	OpGitHubRead   Operation = "github_read"
	OpSecretsList  Operation = "secrets_list"

	OpAgentSpawn   Operation = "agent_spawn"
	OpAgentStatus  Operation = "agent_status"
	OpAgentLogs    Operation = "agent_logs"
	OpAgentMessage Operation = "agent_message"
	OpAgentCancel  Operation = "agent_cancel"
	OpAgentList    Operation = "agent_list"

	// Internal runner RPC for /mcp-gateway. Never listed on public /mcp.
	OpMCPGatewayCatalog       Operation = "mcp_gateway_catalog"
	OpMCPServerGetCredentials Operation = "mcp_server_get_credentials"
	OpMCPServerCreate         Operation = "mcp_server_create"
	OpMCPServerReplaceTools   Operation = "mcp_server_replace_tools"
	OpMCPServerSetPermissions Operation = "mcp_server_set_permissions"
	OpMCPGatewayTraceAppend   Operation = "mcp_gateway_trace_append"
	OpMCPGatewayTraceList     Operation = "mcp_gateway_trace_list"

	// Dashboard-only runner RPCs. Never listed on public /mcp.
	OpPrivilegeGrantList    Operation = "privilege_grant_list"
	OpPrivilegeGrantApprove Operation = "privilege_grant_approve"
	OpPrivilegeGrantReject  Operation = "privilege_grant_reject"
	OpWorkspaceDetail       Operation = "workspace_detail"
	OpWorkspaceCloseFenced  Operation = "workspace_close_fenced"

	OpMCPServerList       Operation = "mcp_server_list"
	OpMCPServerGet        Operation = "mcp_server_get"
	OpMCPServerUpdate     Operation = "mcp_server_update"
	OpMCPServerDelete     Operation = "mcp_server_delete"
	OpMCPServerSetEnabled Operation = "mcp_server_set_enabled"

	OpKnowledgeDashboardList       Operation = "knowledge_dashboard_list"
	OpKnowledgeDashboardGet        Operation = "knowledge_dashboard_get"
	OpKnowledgeDashboardCreate     Operation = "knowledge_dashboard_create"
	OpKnowledgeDashboardUpdate     Operation = "knowledge_dashboard_update"
	OpKnowledgeDashboardDelete     Operation = "knowledge_dashboard_delete"
	OpKnowledgeDashboardSearch     Operation = "knowledge_dashboard_search"
	OpKnowledgeDashboardGraph      Operation = "knowledge_dashboard_graph"
	OpKnowledgeDashboardLinkCreate Operation = "knowledge_dashboard_link_create"
	OpKnowledgeDashboardLinkDelete Operation = "knowledge_dashboard_link_delete"

	OpArtifactList     Operation = "artifact_list"
	OpArtifactSnapshot Operation = "artifact_snapshot"
	OpArtifactRead     Operation = "artifact_read"
	OpArtifactRestore  Operation = "artifact_restore"
	OpArtifactDelete   Operation = "artifact_delete"

	OpAuditList Operation = "audit_list"

	OpGitHubStatus        Operation = "github_status"
	OpGitHubSetupBegin    Operation = "github_setup_begin"
	OpGitHubSetupComplete Operation = "github_setup_complete"
	OpGitHubReconcile     Operation = "github_reconcile"
	OpGitHubDisconnect    Operation = "github_disconnect"

	OpProjectList           Operation = "project_list"
	OpProjectCreate         Operation = "project_create"
	OpProjectUpdate         Operation = "project_update"
	OpProjectDelete         Operation = "project_delete"
	OpEnvironmentList       Operation = "environment_list"
	OpEnvironmentCreate     Operation = "environment_create"
	OpEnvironmentUpdate     Operation = "environment_update"
	OpEnvironmentDelete     Operation = "environment_delete"
	OpSecretList            Operation = "secret_list"
	OpSecretCreate          Operation = "secret_create"
	OpSecretRotate          Operation = "secret_rotate"
	OpSecretUpdate          Operation = "secret_update"
	OpSecretDelete          Operation = "secret_delete"
	OpSecretBulkApply       Operation = "secret_bulk_apply"
	OpGlobalSecretList      Operation = "global_secret_list"
	OpGlobalSecretCreate    Operation = "global_secret_create"
	OpGlobalSecretRotate    Operation = "global_secret_rotate"
	OpGlobalSecretUpdate    Operation = "global_secret_update"
	OpGlobalSecretDelete    Operation = "global_secret_delete"
	OpGlobalSecretBulkApply Operation = "global_secret_bulk_apply"

	OpModelCredentialList   Operation = "model_credential_list"
	OpModelCredentialCreate Operation = "model_credential_create"
	OpModelCredentialRotate Operation = "model_credential_rotate"
	OpModelCredentialDelete Operation = "model_credential_delete"
	OpModelProfileList      Operation = "model_profile_list"
	OpModelProfileCreate    Operation = "model_profile_create"
	OpModelProfileUpdate    Operation = "model_profile_update"
	OpModelProfileActivate  Operation = "model_profile_activate"
	OpModelProfileDisable   Operation = "model_profile_disable"
	OpModelProfileDelete    Operation = "model_profile_delete"
	OpModelConfigStatus     Operation = "model_config_status"

	OpSkillList           Operation = "skill_list"
	OpSkillGet            Operation = "skill_get"
	OpSkillCreateCustom   Operation = "skill_create_custom"
	OpSkillUpdate         Operation = "skill_update"
	OpSkillArchive        Operation = "skill_archive"
	OpSkillRestore        Operation = "skill_restore"
	OpSkillBulk           Operation = "skill_bulk"
	OpSkillUsage          Operation = "skill_usage"
	OpSkillSearch         Operation = "skill_search"
	OpSkillRevisionList   Operation = "skill_revision_list"
	OpSkillRevisionGet    Operation = "skill_revision_get"
	OpSkillRevisionDiff   Operation = "skill_revision_diff"
	OpSkillRevisionCreate Operation = "skill_revision_create"
	OpSkillRevisionFork   Operation = "skill_revision_fork"
	OpSkillImportStart    Operation = "skill_import_start"
	OpSkillImportStatus   Operation = "skill_import_status"
	OpSkillImportCancel   Operation = "skill_import_cancel"
	OpSkillSetList        Operation = "skill_set_list"
	OpSkillSetGet         Operation = "skill_set_get"
	OpSkillSetCreate      Operation = "skill_set_create"
	OpSkillSetUpdate      Operation = "skill_set_update"
	OpSkillSetDelete      Operation = "skill_set_delete"
	OpSkillSetPreview     Operation = "skill_set_preview"

	OpToolkitsList         Operation = "toolkits_list"
	OpToolkitsPreview      Operation = "toolkits_preview"
	OpSettingsGet          Operation = "settings_get"
	OpSettingsUpdate       Operation = "settings_update"
	OpSettingsNetworkCheck Operation = "settings_network_check"

	OpToolkitRegistryList    Operation = "toolkit_registry_list"
	OpToolkitRegistryUpdate  Operation = "toolkit_registry_update"
	OpToolkitRegistryRefresh Operation = "toolkit_registry_refresh"
)

// AllOperations is the ordered public MCP tool catalog from RunnerOperationSchema.
var AllOperations = []Operation{
	OpWorkspaceOpen, OpWorkspaceList, OpWorkspaceStatus, OpWorkspaceCapabilities, OpWorkspaceClose,
	OpWorkspaceLeaseRenew, OpWorkspaceRecover, OpWorkspaceContext, OpWorkspaceSetActive,
	OpWorkspaceFinalize,
	OpFilesList, OpFilesRead, OpFilesWrite, OpFilesWriteBatch, OpFilesApplyPatch, OpFilesDelete, OpFilesMove, OpFilesMkdir, OpGrepSearch,
	OpSymbolsSearch, OpSymbolsReferences,
	OpExecRun, OpShellOpen, OpShellIO, OpShellClose,
	OpSessionsList, OpSessionsOpen, OpSessionsIO, OpSessionsClose,
	OpTasksList, OpTasksRun, OpTasksStatus, OpTasksCancel, OpTasksGraph,
	OpOperationStatus, OpOperationCancel, OpOperationWait,
	OpGitStatus, OpGitDiff, OpGitLog, OpGitBranch, OpGitCheckout, OpGitAdd, OpGitCommit, OpGitFetch, OpGitPull, OpGitPush, OpGitMerge, OpGitRebase,
	OpGitIdentityStatus, OpGitIdentitySet,
	OpWorktreesList, OpWorktreesCreate, OpWorktreesRemove,
	OpSkillsList, OpSkillsRead, OpSkillsRun, OpSkillSuggest,
	OpHooksList, OpHooksRun, OpHooksActivate, OpHooksDeactivate,
	OpMemoriesList, OpMemoriesRead, OpMemoriesWrite, OpMemoriesSearch, OpMemoriesDelete,
	OpKnowledgeCreate, OpKnowledgeRead, OpKnowledgeUpdate, OpKnowledgeDelete, OpKnowledgeList, OpKnowledgeSearch, OpKnowledgeLink, OpKnowledgeUnlink, OpKnowledgeGraph,
	OpDeploymentsList, OpDeploymentsRun,
	OpArtifactsSnapshot, OpArtifactsList, OpArtifactsRead, OpArtifactsRestore, OpArtifactsDelete,
	OpGitHubAction, OpGitHubRead,
	OpSecretsList,
	OpAgentSpawn, OpAgentStatus, OpAgentLogs, OpAgentMessage, OpAgentCancel, OpAgentList,
}

func setOf(ops ...Operation) map[Operation]struct{} {
	m := make(map[Operation]struct{}, len(ops))
	for _, op := range ops {
		m[op] = struct{}{}
	}
	return m
}

var readOnlyOps = setOf(
	OpWorkspaceList, OpWorkspaceStatus, OpWorkspaceCapabilities, OpWorkspaceContext,
	OpFilesList, OpFilesRead, OpGrepSearch, OpSymbolsSearch, OpSymbolsReferences,
	OpSessionsList, OpTasksList, OpTasksStatus, OpTasksGraph,
	OpOperationStatus, OpOperationWait,
	OpGitStatus, OpGitDiff, OpGitLog, OpGitIdentityStatus,
	OpWorktreesList, OpSkillsList, OpSkillsRead, OpHooksList, OpMemoriesList, OpMemoriesRead, OpMemoriesSearch,
	OpKnowledgeRead, OpKnowledgeList, OpKnowledgeSearch, OpKnowledgeGraph, OpDeploymentsList,
	OpArtifactsList, OpArtifactsRead, OpSecretsList, OpGitHubRead,
	OpAgentStatus, OpAgentLogs, OpAgentList,
)

var destructiveOps = setOf(
	OpWorkspaceClose, OpWorkspaceRecover, OpWorkspaceFinalize,
	OpFilesWrite, OpFilesWriteBatch, OpFilesApplyPatch, OpFilesDelete, OpFilesMove,
	OpExecRun, OpShellIO, OpShellClose, OpSessionsIO, OpSessionsClose,
	OpTasksRun, OpTasksCancel, OpOperationCancel,
	OpGitBranch, OpGitCheckout, OpGitPull, OpGitPush, OpGitMerge, OpGitRebase, OpGitIdentitySet,
	OpWorktreesRemove, OpSkillsRun, OpHooksRun, OpHooksActivate, OpHooksDeactivate, OpMemoriesWrite, OpMemoriesDelete,
	OpKnowledgeCreate, OpKnowledgeUpdate, OpKnowledgeDelete, OpKnowledgeLink, OpKnowledgeUnlink,
	OpDeploymentsRun, OpArtifactsRestore, OpArtifactsDelete, OpGitHubAction,
	OpAgentSpawn, OpAgentMessage, OpAgentCancel,
)

var openWorldOps = setOf(
	OpWorkspaceOpen, OpWorkspaceFinalize, OpExecRun, OpShellIO, OpSessionsIO, OpTasksRun,
	OpGitFetch, OpGitPull, OpGitPush, OpSkillsRun, OpSkillSuggest, OpHooksRun, OpDeploymentsRun, OpGitHubAction, OpGitHubRead,
	OpAgentSpawn, OpAgentMessage,
)

// Known reports whether op is a public coding-harness tool.
func (op Operation) Known() bool {
	_, ok := operationIndex[op]
	return ok
}

// Internal reports whether op is a runner-only MCP-gateway RPC.
func (op Operation) Internal() bool {
	switch op {
	case OpMCPGatewayCatalog, OpMCPServerGetCredentials, OpMCPServerCreate, OpMCPServerReplaceTools, OpMCPServerSetPermissions, OpMCPGatewayTraceAppend, OpMCPGatewayTraceList:
		return true
	default:
		return false
	}
}

// Dashboard reports whether op is a runner-only dashboard-control RPC.
func (op Operation) Dashboard() bool {
	switch op {
	case OpPrivilegeGrantList, OpPrivilegeGrantApprove, OpPrivilegeGrantReject, OpWorkspaceDetail, OpWorkspaceCloseFenced,
		OpMCPServerList, OpMCPServerGet, OpMCPServerUpdate, OpMCPServerDelete, OpMCPServerSetEnabled,
		OpKnowledgeDashboardList, OpKnowledgeDashboardGet, OpKnowledgeDashboardCreate, OpKnowledgeDashboardUpdate,
		OpKnowledgeDashboardDelete, OpKnowledgeDashboardSearch, OpKnowledgeDashboardGraph,
		OpKnowledgeDashboardLinkCreate, OpKnowledgeDashboardLinkDelete,
		OpArtifactList, OpArtifactSnapshot, OpArtifactRead, OpArtifactRestore, OpArtifactDelete,
		OpAuditList,
		OpGitHubStatus, OpGitHubSetupBegin, OpGitHubSetupComplete, OpGitHubReconcile, OpGitHubDisconnect,
		OpProjectList, OpProjectCreate, OpProjectUpdate, OpProjectDelete,
		OpEnvironmentList, OpEnvironmentCreate, OpEnvironmentUpdate, OpEnvironmentDelete,
		OpSecretList, OpSecretCreate, OpSecretRotate, OpSecretUpdate, OpSecretDelete, OpSecretBulkApply,
		OpGlobalSecretList, OpGlobalSecretCreate, OpGlobalSecretRotate, OpGlobalSecretUpdate, OpGlobalSecretDelete, OpGlobalSecretBulkApply,
		OpModelCredentialList, OpModelCredentialCreate, OpModelCredentialRotate, OpModelCredentialDelete,
		OpModelProfileList, OpModelProfileCreate, OpModelProfileUpdate, OpModelProfileActivate, OpModelProfileDisable, OpModelProfileDelete,
		OpModelConfigStatus,
		OpSkillList, OpSkillGet, OpSkillCreateCustom, OpSkillUpdate, OpSkillArchive, OpSkillRestore, OpSkillBulk,
		OpSkillUsage, OpSkillSearch,
		OpSkillRevisionList, OpSkillRevisionGet, OpSkillRevisionDiff, OpSkillRevisionCreate, OpSkillRevisionFork,
		OpSkillImportStart, OpSkillImportStatus, OpSkillImportCancel,
		OpSkillSetList, OpSkillSetGet, OpSkillSetCreate, OpSkillSetUpdate, OpSkillSetDelete, OpSkillSetPreview,
		OpToolkitsList, OpToolkitsPreview, OpSettingsGet, OpSettingsUpdate, OpSettingsNetworkCheck,
		OpToolkitRegistryList, OpToolkitRegistryUpdate, OpToolkitRegistryRefresh:
		return true
	default:
		return false
	}
}

var operationIndex map[Operation]struct{}

func init() {
	operationIndex = setOf(AllOperations...)
}

// ReadOnly is the MCP readOnlyHint for this tool.
func (op Operation) ReadOnly() bool {
	_, ok := readOnlyOps[op]
	return ok
}

// Destructive is the MCP destructiveHint for this tool.
func (op Operation) Destructive() bool {
	_, ok := destructiveOps[op]
	return ok
}

// OpenWorld is the MCP openWorldHint for this tool.
func (op Operation) OpenWorld() bool {
	_, ok := openWorldOps[op]
	return ok
}
