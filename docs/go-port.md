# Go port map

Parallel Go sources live next to the TypeScript tree. This document maps
executable owners. Behavior, defaults, and schemas remain owned by the TS
files and `packages/contracts` until a package is marked runtime-of-record.

## Composition roots

| Mode | TypeScript | Go |
| --- | --- | --- |
| Streamable HTTP `/mcp` | `apps/api/src/mcp-server.ts`, `apps/api/src/app.ts` | `cmd/cloud-harness-mcp`, `internal/mcp`, `internal/api` |
| MCP gateway `/mcp-gateway` | `apps/api/src/mcp-gateway/` | `internal/gateway` + runner `mcp_gateway_catalog`/`mcp_server_get_credentials`/`mcp_server_set_permissions`/`mcp_gateway_trace_append`/`mcp_gateway_trace_list` (internal RPCs, not public `/mcp` 92). Catalog and traces persist in `internal/mcpgw` SQLite when `STATE_DB` is set; tests keep the in-memory hub. Trace append scrubs credential-shaped headers plus raw/base64/hex/percent secret forms; the API always sends `secrets: []`. Constant five-tool surface; search/inspect/execute load the runner catalog and record metadata-only traces (arguments/results/credentials never stored); denied execute is an ok `{allowed:false}` envelope and never opens a socket; inspect deny/disabled/unknown is `NOT_FOUND` with the same message; live execute is SSRF-gated, DNS-pinned, no redirects, credentials only on the configured origin+path. Local stdio stays empty/UNAVAILABLE. |
| Local stdio | `apps/api/src/cli-options.ts`, `apps/api/src/local/` | `cmd/cloud-harness-mcp --transport stdio --workspace` (`internal/mcp.ServeStdio` + confined `LocalBackend` including write_batch/move/symbols/git local; `workspace_list`/`status`/`capabilities`/`lease_renew`/`close` plus in-process `git_identity_*`; `git_fetch`/`git_pull` require `--git-network`, `git_push` requires `--git-push`; host `git` stays confined, tokens never in argv; `workspace_open`/`set_active`/`finalize` remain unsupported) |

## Control plane

| Concern | TypeScript owner | Go package |
| --- | --- | --- |
| CLI flags | `apps/api/src/cli-options.ts` | `internal/config`, `cmd/cloud-harness-mcp` |
| Owner bearer / Access JWT | `apps/api/src/auth.ts`, `access-jwt-verifier.ts` | `cmd/cloud-harness-mcp` `ProductionOptions` + `internal/auth`. `AUTH_MODE=cloudflare-access` verifies `Cf-Access-Jwt-Assertion` against team JWKS (https only), ignores opaque client bearer / `chm_key_`, and forwards `principal: {kind:external,issuer,subject}` on each runner RPC. Owner-bearer requires `MCP_BEARER_TOKEN` and forbids Access settings. The raw JWT never appears in logs or runner envelopes. |
| Request security | `apps/api/src/request-security.ts` | `internal/api` (Host/Origin allowlist, `no-store`/`nosniff`/`X-Accel-Buffering`, pre-auth 429) |
| Dashboard BFF | `apps/api/src/dashboard-*.ts` | `internal/api` (later) |
| Ingress proxy | `deploy/ingress-proxy.mjs` | `cmd/ingress-proxy` + `internal/ingress` (raw TCP byte pipe, no secrets, SIGINT/SIGTERM). Opt-in overlay `compose.go.yaml`; TS `compose.yaml` stays shipped |
| API-key Worker | `apps/api-key-gateway` | Keep Wrangler TS (Cloudflare Worker). Go hashes/verifies `chm_key_` secrets in `internal/auth` + `internal/store` and never logs plaintext |
| Public contracts | `packages/contracts/src/` | `pkg/protocol` |
| Runner HTTP RPC | `apps/runner/src/app.ts`, `internal-runner-operations.ts` | `cmd/runner`, `internal/runner` |
| SQLite metadata / state | `apps/runner/src/metadata-store.ts`, `state-store.ts` | `internal/store` (`Memory` + `SQLite` via `database/sql` + `modernc.org/sqlite`; CHECK rejects raw `bridge`; `environment_id` migrates onto existing DBs). `git_operation_idempotency` journals `workspace_finalize` (and later push/commit): same key+fingerprint replays, different fingerprint is CONFLICT, in-flight is retryable CONFLICT. Legacy `finalize_idempotency` rows replay as SUCCEEDED. |
| Secrets keyring | `apps/runner/src/secret-keyring.ts`, `secret-metadata-store.ts` | `internal/secrets` (AES-256-GCM + SQLite envelopes; `secrets_list` returns names/descriptions only; plaintext never stored, listed, or logged) |
| Artifacts | `apps/runner/src/artifact-store.ts` | `internal/artifacts` (confined `objects/` snapshots; `artifacts_list`/`read`/`delete` without an active workspace; snapshot/restore stay path-confined; local stdio remains unsupported) |
| Memories | `apps/runner/src/state-store.ts` memories + `worker/harness-worker.mjs` | `internal/memories` SQLite on the runner (`memories_*` scoped to owner/repository/workspace); local stdio stays confined markdown under `.cloud-harness/memories/` |
| Knowledge | `apps/runner/src/knowledge-store.ts` | `internal/knowledge` SQLite on the runner (`knowledge_create`/`read`/`update`/`delete`/`list`/`search`/`link`/`unlink`/`graph`; FTS5 lexical + local hashed embeddings fused with RRF (`hybrid`/`lexical`/`semantic`/`lexical_fallback`, relevance 0–100); bounded BFS graph; local stdio remains unsupported) |
| Hook activations | `apps/runner/src/state-store.ts` `activateHook`/`deactivateHook` | `internal/hooks` SQLite on the runner (`hooks_activate`/`hooks_deactivate`; SHA-256 pin + TTL; local stdio remains unsupported) |
| Hook execution | `worker/harness-worker.mjs` `hooks_run` | `internal/executor` `hooks_run` (TOCTOU: `expectedManifestSha256`/`expectedSha256` must match the live `.cloud-harness/hooks.json` digest; mismatch is CONFLICT; local stdio is allowed because the command stays confined to the workspace) |
| Skill execution | `apps/runner/src/workspace-service.ts` `runSkillInHelperContainer` + `worker/harness-worker.mjs` `skills_run` | `internal/grants` + disposable Docker helper (`internal/sandbox.SkillHelperArgs`) + `internal/executor` `skills_run` (runner requires an owner privilege grant then launches UID 10001 `--rm` helper; worker snapshot/digest stays inside the helper; no local fallback; `executionMode` is `helper-container`. Local stdio still runs the verified snapshot without a grant and reports `local`) |
| Skill suggestion | `apps/runner/src/dashboard-control-service.ts` `skill_suggest` + TypeSafe suggester | `internal/typesafe` HTTPS suggester (`api.typesafe.ai` only). Redaction fails closed; upstream failure degrades to no suggestion. Prompt/secrets never appear in the result or cache. No key (`TYPESAFE_API_KEY` / `WithTypeSafe`) is `not_configured` with zero outbound calls; missing workspace is `empty_roster`. Local stdio still ranks the confined roster lexically (`outboundCalls: 0`). |
| Deployments | `worker/harness-worker.mjs` `deployments_list`/`deployments_run` | `internal/executor` (confined `.cloud-harness/deployments.json`; list returns only `name`/`cwd`; dash names and oversized files are INVALID_INPUT; nonzero run is CONFLICT) |
| Workspace + Docker policy | `apps/runner/src/workspace-service.ts`, `docker-engine.ts` | `cmd/runner` `ProductionService` + `internal/runner`/`internal/sandbox`. Production wires Docker clone, GitHub App (`GITHUB_APP_*` / `_FILE`), durable `STATE_DB` workspaces plus grants/hooks/memories/knowledge/MCP gateway, and optional TypeSafe. `workspace_open` clones via helper (token on stdin) then creates the executor with `JOBS_ROOT/<id>/repo` mounted at `/workspace`; socket is never mounted. Tests without Docker still use the in-process noop engine. TS `compose.yaml` stays shipped. |
| GitHub App + transfer helpers | `apps/runner/src/github-*.ts`, `worker/*-helper.sh` | `internal/git` (RS256 App JWT + clone/transfer/gh helpers; `git_fetch`/`git_push`/`github_action`/`github_read` mint token onto helper stdin only; import stays `network-none`) |
| Executor worker | `worker/harness-worker.mjs` | `cmd/harness-worker`, `internal/executor` (path confinement, truncation). When Docker is attached the runner dispatches `files_*`/`grep_search`/`symbols_*`/`exec_run`/`git_*`/`worktrees_*`/`skills_list`/`skills_read`/`hooks_list`/`hooks_run`/`deployments_*` via one-shot `docker exec -i` + `worker-runner.sh` (payload on stdin, no tokens in argv). Sessions/shells/tasks stay on the runner as persistent `docker exec`. Tests without Docker still execute the confined job repo in-process. Local stdio also hosts `memories_*` markdown. TS remains image entry until Compose switches. |
| Coding sessions | `apps/runner/src/operation-manager.ts` `openSession`/`sessionIo` | `internal/executor` persistent `docker exec -i` + `shell-runner.sh` when a container is attached (confined cwd, idempotent open, dash names INVALID_INPUT, list omits output). Tests/local stdio still use in-process `/bin/bash`. |
| Interactive shells | `apps/runner/src/operation-manager.ts` `openShell`/`shellIo` | Same persistent `docker exec` path as sessions (`sh_` ids, no name). Not the one-shot worker. |
| Background tasks | `apps/runner/src/operation-manager.ts` `runTask` | Persistent `docker exec` + `task-runner.sh`; command rides `CH_COMMAND` env on the docker CLI child, never argv. `durable_tasks` + `task_dependencies` persist status/fingerprint/boot_id in SQLite (`STATE_DB`) or the in-memory ledger. MCP envelopes keep lowercase `queued`/`running`/`succeeded`; SQLite stores uppercase CHECK values. A runner restart with a new `boot_id` fail-closes leftover QUEUED/RUNNING rows as FAILED `RUNNER_RESTARTED`. |
| Long-running operations | `apps/runner/src/operation-manager.ts` generic tracker | `internal/executor` maps `operation_status`/`cancel`/`wait` onto in-process tasks (`task_` ids) plus a reserved generic `op_` hub; Docker worker pid files stay unwired |
| Model gateway / agents | `apps/model-gateway`, `apps/agent-runtime`, `apps/runner/src/agent-*.ts` | `cmd/model-gateway` Unix control socket (mode 0600) mints hashed leases; `internal/agent.Launcher` creates an internal per-agent network + no-mount UID 10001 container (`AGENT_IMAGE`). Interactive `docker run -i` speaks JSONL (`start`/`message`/`cancel`/`tool_result` in, `event`/`usage`/`tool_request`/`terminal` out). `tool_request` is proxied only for granted `files_*`/`grep`/`symbols_*` ops with `workspaceId` injected; denied, duplicate, or oversized results fail closed as `tool_result` errors. Prompt and lease travel only on that wire; MCP results hash the prompt and never echo the lease. Spawn without a launcher still settles `FAILED`. Local stdio rejects agents. TS Compose remains runtime of record. |

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
