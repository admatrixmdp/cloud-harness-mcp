// Package runner owns workspace lifecycle, principal resolution, and
// orchestration of Docker executors (today apps/runner).
//
// Only this process may hold the Docker socket, job/state mounts, and optional
// GitHub App credentials. Cleanup is scoped by verified workspace identity.
package runner
