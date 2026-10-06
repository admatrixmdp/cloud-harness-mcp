# Cloud Harness MCP — Go port coding rules

This tree is a **parallel Go implementation** of the existing TypeScript
harness. TypeScript remains the runtime of record until the Go binaries are
wired through Compose and verified.

Style target: GoClaw v3.14 (`/Users/mqglobal/Documents/goclaw/goclaw-source-v3.14.0`),
patterns only — **do not copy GoClaw source into this repository**.

## Layout

```
cmd/<binary>/          Cobra mains (cloud-harness-mcp, runner, ingress-proxy, provisioning-proxy, model-gateway)
internal/<pkg>/        private implementation
pkg/protocol/          public MCP/result/id wire types (packages/contracts)
```

## Stack

- Go 1.26, Cobra CLI, `log/slog`, `database/sql` + `modernc.org/sqlite` (no ORM)
- MCP: `github.com/mark3labs/mcp-go` (same family as GoClaw)
- JSON: std `encoding/json`; field names must match Zod contracts
- IDs: opaque prefixed strings from `pkg/protocol`, never derived from paths

## Must preserve

- Public MCP tool names, JSON schemas, and `ToolResult` envelopes
- Ingress is the only host-published Compose service, loopback-bound
- API has no Docker socket / host job mounts; runner is the only Docker authority
- Executor: non-root, read-only rootfs, dropped caps, no-new-privileges, TTL
- Network profiles: `dependency-access` (default) or `network-none` only
- Fail-closed `DEPENDENCY_EGRESS_UNAVAILABLE`; never silent downgrade to bridge
- Credential-free HTTPS remotes; GitHub App tokens only on helper stdin
- Never log tokens, keys, Access assertions, or secret plaintext

## Do not

- Delete or rewrite TypeScript as part of a Go-port task unless the task says so
- Import GoClaw as a module
- Add a selectable `bridge` network profile
- Put credentials in fixtures, remote URLs, or command output
