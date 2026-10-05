# Go port map

Parallel Go sources live next to the TypeScript tree. This document maps
executable owners. Behavior, defaults, and schemas remain owned by the TS
files and `packages/contracts` until a package is marked runtime-of-record.

## Composition roots

| Mode | TypeScript | Go |
| --- | --- | --- |
| Streamable HTTP `/mcp` | `apps/api/src/mcp-server.ts`, `apps/api/src/app.ts` | `cmd/cloud-harness-mcp`, `internal/mcp`, `internal/api` |
| MCP gateway `/mcp-gateway` | `apps/api/src/mcp-gateway/` | `internal/gateway` (constant five-tool surface; execute is SSRF-gated, DNS-pinned, no redirects, credentials only on the configured origin+path) |
| Local stdio | `apps/api/src/cli-options.ts`, `apps/api/src/local/` | `cmd/cloud-harness-mcp --transport stdio --workspace` (`internal/mcp.ServeStdio` + confined `LocalBackend` including write_batch/move/symbols/git local; fetch/push stay gated on `--git-network`/`--git-push`; `workspace_open` remains unsupported) |

## Control plane

| Concern | TypeScript owner | Go package |
| --- | --- | --- |
| CLI flags | `apps/api/src/cli-options.ts` | `internal/config`, `cmd/cloud-harness-mcp` |
| Owner bearer / Access JWT | `apps/api/src/auth.ts`, `access-jwt-verifier.ts` | `internal/auth` (RS256 Access JWT + JWKS; Access mode ignores opaque client bearer) |
| Request security | `apps/api/src/request-security.ts` | `internal/api` (Host/Origin allowlist, `no-store`/`nosniff`/`X-Accel-Buffering`, pre-auth 429) |
| Dashboard BFF | `apps/api/src/dashboard-*.ts` | `internal/api` (later) |
| Ingress proxy | `deploy/ingress-proxy.mjs` | `cmd/ingress-proxy` + `internal/ingress` (raw TCP byte pipe, no secrets, SIGINT/SIGTERM). Opt-in overlay `compose.go.yaml`; TS `compose.yaml` stays shipped |
| API-key Worker | `apps/api-key-gateway` | Keep Wrangler TS (Cloudflare Worker). Go hashes/verifies `chm_key_` secrets in `internal/auth` + `internal/store` and never logs plaintext |
| Public contracts | `packages/contracts/src/` | `pkg/protocol` |
| Runner HTTP RPC | `apps/runner/src/app.ts`, `internal-runner-operations.ts` | `cmd/runner`, `internal/runner` |
| SQLite metadata / state | `apps/runner/src/metadata-store.ts`, `state-store.ts` | `internal/store` (`Memory` + `SQLite` via `database/sql` + `modernc.org/sqlite`; CHECK rejects raw `bridge`; `environment_id` migrates onto existing DBs) |
| Secrets keyring | `apps/runner/src/secret-keyring.ts`, `secret-metadata-store.ts` | `internal/secrets` (AES-256-GCM + SQLite envelopes; `secrets_list` returns names/descriptions only; plaintext never stored, listed, or logged) |
| Artifacts | `apps/runner/src/artifact-store.ts` | `internal/artifacts` (confined `objects/` snapshots; `artifacts_list`/`read`/`delete` without an active workspace; snapshot/restore stay path-confined; local stdio remains unsupported) |
| Workspace + Docker policy | `apps/runner/src/workspace-service.ts`, `docker-engine.ts` | `internal/runner`, `internal/sandbox` (`workspace_open` clones via helper container when a cloner is wired; minted token on stdin only; `workspace_lease_renew` caps at hard expiry; `workspace_recover` resume/status/patch/export; `workspace_context` / `workspace_set_active`) |
| GitHub App + transfer helpers | `apps/runner/src/github-*.ts`, `worker/*-helper.sh` | `internal/git` (RS256 App JWT + clone/transfer/gh helpers; `git_fetch`/`git_push`/`github_action`/`github_read` mint token onto helper stdin only; import stays `network-none`) |
| Executor worker | `worker/harness-worker.mjs` | `cmd/harness-worker`, `internal/executor` (path confinement, truncation; runner dispatches `files_*`/`grep_search`/`symbols_*`/`exec_run`/`git_*`/`worktrees_*` local through the confined job repo; TS remains image entry until Compose switches) |
| Model gateway / agents | `apps/model-gateway`, `apps/agent-runtime`, `apps/runner/src/agent-*.ts` | `cmd/model-gateway`, `internal/agent` (opaque hashed leases, lease-gated HTTPS upstream, credential never logged or echoed). TS Compose remains runtime of record; Go images live in `docker/go-*.Dockerfile` |

## MUST-preserve security invariants

Source of truth: `docs/security-model.md`, `AGENTS.md`.

1. Private single-owner (or mutually trusted operators) threat model. Not a hostile multi-tenant sandbox.
2. Only the credential-free ingress proxy publishes a host port; bind loopback. API and runner do not publish host ports. Ingress has no secrets and does not join the control network.
3. Docker socket, job/state mounts, GitHub App credentials: runner only.
4. Executors: non-root, read-only rootfs, dropped capabilities, `no-new-privileges`, resource limits, TTL, one writable repo mount, no Docker socket, no control-plane credentials.
5. Network: default `dependency-access` (public DNS + TCP 80/443, attested host firewall). `network-none` is the isolation opt-out. No raw `bridge` profile. Attestation failure → `DEPENDENCY_EGRESS_UNAVAILABLE`, never a silent downgrade.
6. Credential-free HTTPS repository URLs. Private-clone tokens stay in the broker/helper stdin. Exception: operator-injected `GH_TOKEN`/`GITHUB_TOKEN` for workspace `gh`.
7. Public MCP schemas and result envelopes in `packages/contracts` / `pkg/protocol`.
8. Cleanup scoped by verified workspace identity, canonical job path, state record, and managed-container labels.
9. Never commit `.env`, tokens, keys, databases, runtime state, or user data.

## GoClaw alignment (patterns, not code)

| GoClaw | Cloud Harness Go |
| --- | --- |
| `cmd/` + `internal/` + `pkg/protocol` | same |
| Cobra | same |
| `mark3labs/mcp-go` | MCP client/server |
| `modernc.org/sqlite` + `database/sql` | metadata store |
| `internal/sandbox` Docker helpers | Docker API style only; **policy is Cloud Harness**, not GoClaw mode/off defaults |
| slog / structured logs | slog; never log secrets |

Do not `require` `github.com/nextlevelbuilder/goclaw`.

## Test parity

Unit tests live next to the Go packages (`go test ./...`). TypeScript tests
remain until Compose switches. Docker-dependent checks use the `docker` build
tag (`go test -tags docker ./internal/sandbox`) and must not weaken host-side
policy assertions when the daemon is unavailable.

Go Compose images (`docker/go-*.Dockerfile`) and healthchecks (`--healthcheck`)
are wired only through `compose.go.yaml`. `scripts/verify-go-compose-overlay.mjs`
asserts the overlay does not publish extra ports, remount the Docker socket, or
inject secrets, and that `compose.yaml` still ships TypeScript.
