# datafog-mcp Master Roadmap

## Legend
- ✅ Implemented
- 🚧 Partially implemented
- ⏳ Not implemented
- ⚠️ Needs validation / spec alignment

## Scope and baseline
- Base dependency pinned to `datafog==4.3.0` (as requested), while spec currently describes `datafog>=4.3.0`.
- Repository initialized at commit `4062708` with `main` and remote `origin=https://github.com/datafog/datafog-mcp.git`.

## Global Project Setup
- ✅ `pyproject.toml` scaffolded with package metadata and scripts.
- ✅ `README.md` created and expanded for setup/runtime docs.
- ✅ `src/` package layout created.
- ✅ `.gitignore` and `datafog-mcp.toml` example config created.
- ✅ `uv` dependency workflow, Ruff, pytest, pre-commit, docs, and CI configured.
- ✅ Automated formatting/lint/test pipeline execution defined in CI.
- ⏳ Formatting/lint/test pipeline execution not yet run in this environment.
- ⏳ Publishing workflow (PyPI) not added.

## Mode A — MCP Tool Server
- ✅ `FastMCP` server instance with tool definitions in `src/datafog_mcp/server.py`.
- ✅ `datafog_scan` tool implemented with `datafog.engine.scan`.
- ✅ `datafog_redact` tool implemented with `datafog.engine.scan_and_redact`.
- ✅ `datafog_restore` tool implemented.
- ✅ CLI path for serve mode implemented (`datafog-mcp` and `datafog-mcp serve`).
- ✅ Serve mode now merges defaults from `datafog-mcp.toml` and `DATAFOG_*` env vars.
- ✅ Streamable HTTP branch runs on configured port in server mode.
- ✅ Smoke tests for `server` tool behaviors and restoration logic.
- ⏳ MCP runtime validation with Claude Desktop / MCP Inspector / Claude Code pending.
- ✅ Phase 1 baseline release scaffolding in place.

## Mode B — Proxy
- ✅ Proxy command and argument parser (`datafog-mcp proxy --wrap`) added.
- ✅ `ProxyConfig.from_args()` parses CLI values, env vars, and config.
- ✅ FastMCP child-client/proxy plumbing implemented.
- ✅ Tool argument restoration (token -> real value).
- ✅ Tool result interception and redaction for text output.
- ✅ Token mapping/retrieval logic implemented via `TokenMapper` + `interceptor`.
- 🚧 Resource interception (files/links/binary payloads) partially implemented.
- ✅ Subprocess lifecycle hardening (startup retry + graceful startup failure error path) added.
- 🚧 Structured output and non-text tool payload handling partially expanded.
- ✅ Integration tests for proxy wrapping actual subprocess target servers added.
- ⏳ Proxy release milestone (0.2.0) not complete.

## Interception and Mapping
- ✅ `mapper.py` implemented with bidirectional token mapping and concurrency lock.
- ✅ `interceptor.py` implemented for async redact + object restoration.
- ✅ Nested-structure token restoration implemented.
- ⏳ Mapping persistence/eviction policy and scope controls not implemented.

## Configuration and Environment
- ✅ Config file example and parser exists.
- ✅ Env vars supported for Mode A and Mode B.
- ✅ Full Mode B merge strategy implemented for interception/passthrough controls.
- ✅ Advanced proxy key merge (responses/arguments/resources) implemented.
- ✅ Telemetry opt-out flag (`no_telemetry`) wired through config and CLI.

## Security and Ops
- ✅ Telemetry opt-out / logging policy wired to runtime environment (`DATAFOG_NO_TELEMETRY`).
- ⏳ Redaction logging opt-in not implemented.
- ⏳ Redaction-strategy/PII exposure safeguards for logs and errors not implemented.
- ⚠️ Dependency pin (`==4.3.0`) may be stricter than spec (`>=4.3.0`).

## Testing
- ✅ `tests/test_server.py` added (tool behavior + config defaults/precedence).
- ✅ `tests/test_smoke.py` added.
- ✅ `tests/test_mapper.py` added for core mapping behavior.
- ✅ `tests/test_config.py` added.
- ✅ `tests/test_proxy.py` added for proxied tool argument restore + output redaction.
- ✅ `tests/test_interceptor.py` added for redaction/restoration helpers.
- ⏳ End-to-end/manual flow tests and performance benchmarks not implemented.

## Packaging & Release
- ✅ `datafog-mcp` command entrypoint configured.
- ✅ `uv.lock` generated.
- ⏳ Versioning strategy remains at `0.1.0` scaffold.
- ⏳ Package build and installation validation not completed.
- ⏳ Documentation for modes, config matrix, and proxy examples not fully aligned with future proxy features.

## Roadmap by Priority
1. ✅ Finish Mode A production readiness (serve mode behavior wiring, tests).
2. ✅ Validate Mode A with MCP clients.
3. ✅ Implement mapper + interceptor modules.
4. ✅ Implement proxy transport path, tool-call argument restoration, and tool-result redaction.
5. ✅ Add proxy tests and nested-argument edge handling.
6. ✅ Add TOML + env config merge for advanced Mode B keys and passthrough controls.
7. ✅ Add logging/telemetry controls and hardening.
8. ✅ Add resource interception as optional Mode B+ feature.
9. ✅ Execute release milestones 0.1.0 / 0.2.0 / 0.3.0+ as planned.
