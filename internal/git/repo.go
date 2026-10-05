package git

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bestagentkits/cloud-harness-mcp/pkg/protocol"
)

// Repository is owner/name parsed from a GitHub HTTPS URL.
type Repository struct {
	Owner string
	Name  string
}

// ParseGitHubRepository requires exactly one owner and one repository.
func ParseGitHubRepository(u *url.URL) (Repository, error) {
	path := strings.TrimPrefix(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Repository{}, fmt.Errorf("%s: GitHub repository URL must identify one owner and repository", protocol.ErrorInvalidInput)
	}
	return Repository{Owner: strings.ToLower(parts[0]), Name: strings.ToLower(parts[1])}, nil
}

// PermissionScope is a GitHub App installation permission group.
type PermissionScope string

const (
	ScopeIssues       PermissionScope = "issues"
	ScopePullRequests PermissionScope = "pull_requests"
	ScopeContents     PermissionScope = "contents"
)

// ActionPermission is the installation grant an action needs.
type ActionPermission struct {
	Scope PermissionScope
	Write bool
}

var githubActionPermissions = map[string]ActionPermission{
	"issue_list":           {Scope: ScopeIssues, Write: false},
	"issue_view":           {Scope: ScopeIssues, Write: false},
	"issue_create":         {Scope: ScopeIssues, Write: true},
	"issue_comment":        {Scope: ScopeIssues, Write: true},
	"issue_comment_update": {Scope: ScopeIssues, Write: true},
	"issue_update":         {Scope: ScopeIssues, Write: true},
	"issue_publish":        {Scope: ScopeIssues, Write: true},
	"label_create":         {Scope: ScopeIssues, Write: true},
	"issue_labels_add":     {Scope: ScopeIssues, Write: true},
	"issue_labels_remove":  {Scope: ScopeIssues, Write: true},
	"pr_list":              {Scope: ScopePullRequests, Write: false},
	"pr_view":              {Scope: ScopePullRequests, Write: false},
	"pr_create":            {Scope: ScopePullRequests, Write: true},
	"pr_update":            {Scope: ScopePullRequests, Write: true},
	"pr_comment":           {Scope: ScopePullRequests, Write: true},
	"commit_list":          {Scope: ScopeContents, Write: false},
	"compare":              {Scope: ScopeContents, Write: false},
	"release_list":         {Scope: ScopeContents, Write: false},
	"tag_list":             {Scope: ScopeContents, Write: false},
}

// RequiredGitHubPermissions returns the App scope for a github_action name.
func RequiredGitHubPermissions(action string) (ActionPermission, bool) {
	p, ok := githubActionPermissions[action]
	return p, ok
}

// RedactToken replaces a minted token in helper output so it never reaches logs.
func RedactToken(text, token string) string {
	if token == "" {
		return text
	}
	return strings.ReplaceAll(text, token, "[redacted]")
}
