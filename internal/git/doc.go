// Package git is the GitHub App broker and transfer-helper boundary.
//
// Short-lived tokens travel only on stdin of an ephemeral helper container.
// Stored remotes and executor checkouts stay credential-free HTTPS URLs.
// The documented owner-opt-in exception is an injected GH_TOKEN/GITHUB_TOKEN
// runtime secret for the workspace gh CLI.
package git
