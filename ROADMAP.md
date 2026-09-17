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
- ✅ `README.md` created (basic install/run overview).
- ✅ `src/` package layout created.
- ✅ `.gitignore` and `datafog-mcp.toml` example config created.
- ⏳ Automated formatting/lint/test pipeline not added.
- ⏳ Publishing workflow (PyPI) not added.

## Mode A — MCP Tool Server
- ✅ `FastMCP` server instance with tool definitions in `src/datafog_mcp/server.py`.
- ✅ `datafog_scan` tool implemented with `datafog.engine.scan`.
- ✅ `datafog_redact` tool implemented with `datafog.engine.scan_and_redact`.
- ✅ `datafog_restore` tool implemented.
- ✅ CLI path for serve mode implemented (`datafog-mcp` and `datafog-mcp serve`).
- 🚧 Streamable HTTP transport listed and parser argument exists, but transport implementation not explicitly validated.
- ⏳ CLI/config option handling for runtime control in serve mode not yet applied to tool behavior (server ignores `--engine`, `--config`, `--verbose`, `--port`).
- ⏳ Unit tests for `server.py` not present.
- ⏳ MCP runtime validation with Claude Desktop / MCP Inspector / Claude Code not done.
- ⏳ Phase 1 release (0.1.0 publish) not complete.

## Mode B — Proxy
- ✅ Proxy command and argument parser (`datafog-mcp proxy --wrap`) added.
- ✅ `ProxyConfig.from_args()` parses CLI values and builds command + entity list parsing.
- 🚧 `src/datafog_mcp/proxy.py` present but currently a scaffold; raises `NotImplementedError`.
- ⏳ FastMCP child-client/proxy plumbing not implemented.
- ⏳ Tool response interception (PII redaction, mapping capture) not implemented.
- ⏳ Tool argument restoration (token -> real value) not implemented.
- ⏳ Resource interception not implemented.
- ⏳ Subprocess lifecycle (start/stop/error handling/cancellation/shutdown) not implemented.
- ⏳ Integration tests for proxy wrapping target servers not implemented.
- ⏳ Proxy release milestone (0.2.0) not complete.

## Interception and Mapping
- ⏳ `mapper.py` not implemented.
- ⏳ `interceptor.py` not implemented.
- ⏳ Nested-structure token restoration not implemented (current roadmap expects future support at object/array levels).
- ⏳ Mapping persistence/eviction policy and scope controls not implemented.

## Configuration and Environment
- ✅ Example TOML config file created with `[server]` and `[proxy]` keys.
- ⏳ `.toml`/environment variable config loading not implemented (`DATAFOG_*` vars unsupported).
- ⏳ Runtime config merge strategy (CLI > env > TOML > defaults) not implemented.
- ⏳ Entity/passthrough config validation not implemented.

## Security and Ops
- ⏳ Telemetry opt-out / logging policy not implemented.
- ⏳ Redaction logging opt-in not implemented.
- ⏳ Redaction-strategy/PII exposure safeguards for logs and errors not implemented.
- ⚠️ Current dependency pin (`==4.3.0`) may be stricter than spec (`>=4.3.0`); decide when to allow newer versions.

## Testing
- ⏳ `tests/test_server.py` not created.
- ⏳ `tests/test_proxy.py` not created.
- ⏳ `tests/test_mapper.py` not created.
- ⏳ `tests/test_interceptor.py` not created.
- ⏳ End-to-end/manual flow tests and performance benchmarks not implemented.

## Packaging & Release
- ⏳ Versioning strategy is still at `0.1.0` scaffold state.
- ⏳ `datafog-mcp` command entrypoint configured; package build/installation process not validated.
- ⏳ Documentation for modes, config matrix, and proxy examples not fully aligned with spec.

## Roadmap by Priority
1. ✅ Complete Mode A production readiness (serve mode behavior wiring, docs, tests).
2. ✅ Finish Mode A validation with MCP clients.
3. ✅ Implement mapper + interceptor modules.
4. ✅ Implement proxy transport path, tool-call argument restoration, and tool-result redaction.
5. ✅ Add proxy tests and nested-argument edge handling.
6. ✅ Add TOML + env config merge and passthrough controls.
7. ✅ Add logging/telemetry controls and hardening.
8. ✅ Add resource interception as optional Mode B+ feature.
9. ✅ Execute release milestones 0.1.0 / 0.2.0 / 0.3.0+ as planned.
