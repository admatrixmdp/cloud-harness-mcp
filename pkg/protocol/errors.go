package protocol

// ErrorCode is the public MCP/result error taxonomy from packages/contracts.
type ErrorCode string

const (
	ErrorAuthenticationFailed             ErrorCode = "AUTHENTICATION_FAILED"
	ErrorForbidden                        ErrorCode = "FORBIDDEN"
	ErrorInvalidInput                     ErrorCode = "INVALID_INPUT"
	ErrorNotFound                         ErrorCode = "NOT_FOUND"
	ErrorConflict                         ErrorCode = "CONFLICT"
	ErrorExpired                          ErrorCode = "EXPIRED"
	ErrorLimitExceeded                    ErrorCode = "LIMIT_EXCEEDED"
	ErrorTimeout                          ErrorCode = "TIMEOUT"
	ErrorCancelled                        ErrorCode = "CANCELLED"
	ErrorUnavailable                      ErrorCode = "UNAVAILABLE"
	ErrorInternal                         ErrorCode = "INTERNAL_ERROR"
	ErrorPrivilegeApprovalRequired        ErrorCode = "PRIVILEGE_APPROVAL_REQUIRED"
	ErrorRepositoryOperationNotAuthorized ErrorCode = "REPOSITORY_OPERATION_NOT_AUTHORIZED"
	ErrorGitHubPermissionMissing          ErrorCode = "GITHUB_PERMISSION_MISSING"
	ErrorGitHubRateLimited                ErrorCode = "GITHUB_RATE_LIMITED"
	ErrorInvalidPullRequestBase           ErrorCode = "INVALID_PULL_REQUEST_BASE"
	ErrorGitHubActionFailed               ErrorCode = "GITHUB_ACTION_FAILED"
	ErrorUnknownRemoteState               ErrorCode = "UNKNOWN_REMOTE_STATE"
	ErrorStaleHead                        ErrorCode = "STALE_HEAD"
	ErrorStaleGeneration                  ErrorCode = "STALE_GENERATION"
	ErrorNoExecutableAssets               ErrorCode = "NO_EXECUTABLE_ASSETS"
	ErrorRunnerRestarted                  ErrorCode = "RUNNER_RESTARTED"
	ErrorDependencyEgressUnavailable      ErrorCode = "DEPENDENCY_EGRESS_UNAVAILABLE"
	ErrorHookFailed                       ErrorCode = "HOOK_FAILED"
	ErrorExecutionFailed                  ErrorCode = "EXECUTION_FAILED"
)
