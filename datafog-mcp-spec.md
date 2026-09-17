# datafog-mcp — Implementation Specification

## Overview

`datafog-mcp` is a Python MCP server that brings PII detection and redaction to any AI agent. It ships as a separate package (`pip install datafog-mcp`) with `datafog>=4.3.0` as a dependency.

Two modes:

- **Mode A (Tool Server):** Exposes `datafog_scan` and `datafog_redact` tools that any MCP client can call. The agent decides when to use them. Simple, ships first.

- **Mode B (Proxy):** Wraps another MCP server and automatically intercepts all tool responses, scanning and redacting PII before it reaches the agent's context window. No agent cooperation needed. Higher value, ships second.

**Stack:** Python 3.10+, FastMCP 2.x, datafog>=4.3.0
**Repo:** `github.com/DataFog/datafog-mcp`
**Distribution:** `pip install datafog-mcp` / `uvx datafog-mcp`

---

## Why Python, Not TypeScript

The entire value proposition is calling `datafog.engine.scan()` — a Python function that runs regex + GLiNER cascade in ~2-15ms. A TypeScript MCP server would need to call the Python engine across a process boundary (subprocess, HTTP, or custom IPC), adding latency, complexity, and a serialization layer in the critical path of every tool response interception.

Python MCP server means direct function call, zero IPC. The proxy is I/O-bound (routing JSON-RPC messages over stdio), which Python async handles fine. Distribution via `uvx datafog-mcp` is as clean as `npx`. And when the Rust core ships with PyO3 bindings, the Python MCP server gets the speed upgrade for free.

---

## Architecture

### Mode A: Tool Server

```
┌───────────┐           ┌────────────────────┐
│  Agent    │──stdio──▶ │  datafog-mcp       │
│ (Claude)  │◀──stdio── │                    │
└───────────┘           │  Tools:            │
                        │  • datafog_scan    │
                        │  • datafog_redact  │
                        │  • datafog_config  │
                        │                    │
                        │  ┌──────────────┐  │
                        │  │ datafog      │  │
                        │  │ .engine      │  │
                        │  │ .scan()      │  │
                        │  │ .redact()    │  │
                        │  └──────────────┘  │
                        └────────────────────┘
```

The agent has tools available and chooses when to call them. Good for prompt-engineering scenarios where the agent is instructed to scan inputs/outputs.

### Mode B: Proxy

```
┌───────────┐        ┌──────────────────┐        ┌──────────────┐
│  Agent    │──stdio─▶│  datafog-mcp    │──stdio─▶│  Target MCP  │
│ (Claude)  │◀─stdio──│  (proxy)        │◀─stdio──│  Server      │
└───────────┘        │                  │        │ (postgres,   │
                     │ intercepts       │        │  slack,      │
                     │ tools/call       │        │  filesystem) │
                     │ responses and    │        └──────────────┘
                     │ scans for PII    │
                     │                  │
                     │ ┌──────────────┐ │
                     │ │ datafog      │ │
                     │ │ .engine      │ │
                     │ │ .scan()      │ │
                     │ │ .redact()    │ │
                     │ └──────────────┘ │
                     │                  │
                     │ ┌──────────────┐ │
                     │ │ token mapper │ │
                     │ │ [EMAIL_1] ↔  │ │
                     │ │ real value   │ │
                     │ └──────────────┘ │
                     └──────────────────┘
```

The proxy sits between the agent and any MCP server. The agent doesn't know it's there. Every tool response passes through the DataFog engine. PII is replaced with tokens. When the agent sends a tool call containing tokens, the proxy restores the real values before forwarding to the target server.

---

## Package Structure

```
datafog-mcp/
├── pyproject.toml
├── README.md
├── src/
│   └── datafog_mcp/
│       ├── __init__.py
│       ├── __main__.py          # CLI entry: `python -m datafog_mcp` or `datafog-mcp`
│       ├── server.py            # Mode A: FastMCP tool server
│       ├── proxy.py             # Mode B: FastMCP proxy with interception
│       ├── mapper.py            # Bidirectional PII token ↔ real value mapping
│       ├── interceptor.py       # Response interception and scanning logic
│       └── config.py            # Configuration loading (TOML/env vars)
├── datafog-mcp.toml             # Example config
└── tests/
    ├── test_server.py
    ├── test_proxy.py
    ├── test_mapper.py
    └── test_interceptor.py
```

---

## Mode A: Tool Server — Detailed Design

### Tools Exposed

#### `datafog_scan`

Scans text for PII and returns detected entities.

```python
@mcp.tool()
def datafog_scan(
    text: str,
    engine: str = "smart",
    entity_types: list[str] | None = None,
) -> dict:
    """Scan text for personally identifiable information (PII).

    Returns a list of detected PII entities with their types, positions,
    and confidence scores. Does not modify the input text.

    Args:
        text: The text to scan for PII
        engine: Detection engine - "regex" (fast), "smart" (best accuracy), "gliner", or "spacy"
        entity_types: Optional list of entity types to detect (e.g., ["EMAIL", "SSN", "PERSON"]).
                      If not specified, detects all supported types.

    Returns:
        Dictionary with 'entities' list and 'summary' of what was found.
    """
    from datafog.engine import scan

    result = scan(text=text, engine=engine, entity_types=entity_types)

    return {
        "entity_count": len(result.entities),
        "entities": [
            {
                "type": e.type,
                "text": e.text,
                "start": e.start,
                "end": e.end,
                "confidence": e.confidence,
            }
            for e in result.entities
        ],
        "engine_used": result.engine_used,
    }
```

#### `datafog_redact`

Scans and redacts PII, returning cleaned text and a reversible mapping.

```python
@mcp.tool()
def datafog_redact(
    text: str,
    engine: str = "smart",
    entity_types: list[str] | None = None,
    strategy: str = "token",
) -> dict:
    """Scan text for PII and redact it, returning cleaned text.

    Replaces PII with tokens like [EMAIL_1], [PERSON_1], etc. The mapping
    between tokens and original values is returned so the operation can be
    reversed if needed.

    Args:
        text: The text to scan and redact
        engine: Detection engine - "regex" (fast), "smart" (best accuracy)
        entity_types: Optional list of entity types to redact
        strategy: Redaction strategy - "token" ([EMAIL_1]), "mask" (████), or "hash"

    Returns:
        Dictionary with 'redacted_text', 'mapping' (token→original), and 'entities'.
    """
    from datafog.engine import scan_and_redact

    result = scan_and_redact(
        text=text, engine=engine, entity_types=entity_types, strategy=strategy
    )

    return {
        "redacted_text": result.redacted_text,
        "mapping": result.mapping,
        "entity_count": len(result.entities),
    }
```

#### `datafog_restore`

Reverses redaction using a previously returned mapping.

```python
@mcp.tool()
def datafog_restore(text: str, mapping: dict[str, str]) -> dict:
    """Restore previously redacted PII using a token mapping.

    Takes redacted text and a mapping (from datafog_redact) and replaces
    tokens with their original values.

    Args:
        text: Redacted text containing tokens like [EMAIL_1]
        mapping: Token-to-original mapping from a previous datafog_redact call

    Returns:
        Dictionary with 'restored_text'.
    """
    restored = text
    # Replace longest tokens first to avoid partial matches
    for token, original in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
        restored = restored.replace(token, original)
    return {"restored_text": restored}
```

### Server Implementation

```python
# src/datafog_mcp/server.py

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="datafog",
    version="0.1.0",
    description="PII detection and redaction tools. Scan text for emails, SSNs, "
                "names, phone numbers, and more. Runs locally — no data leaves your machine.",
)

# Register tools (as above)

def run_server(transport: str = "stdio"):
    mcp.run(transport=transport)
```

### Claude Desktop Config (Mode A)

```json
{
  "mcpServers": {
    "datafog": {
      "command": "uvx",
      "args": ["datafog-mcp"]
    }
  }
}
```

Or if installed via pip:

```json
{
  "mcpServers": {
    "datafog": {
      "command": "datafog-mcp"
    }
  }
}
```

### Claude Code Config (Mode A)

```bash
claude mcp add datafog -- uvx datafog-mcp
```

---

## Mode B: Proxy — Detailed Design

### Core Concept

DataFog launches the target MCP server as a child process and sits on its stdio streams. To the agent, DataFog looks like the target server (it forwards all capabilities). To the target server, DataFog looks like a normal MCP client.

FastMCP 2.0's built-in proxy support handles most of the protocol plumbing. What we add is an interception layer that scans and redacts PII in tool responses.

### Interception Points

**1. Tool Responses (outbound — critical)**

When the target server returns a `tools/call` result, intercept the response content. For each `TextContent` block, run `datafog.engine.scan_and_redact()` and replace the text with the redacted version. Store the token↔value mapping.

```python
# Pseudocode for the interception
async def intercept_tool_response(response: CallToolResult) -> CallToolResult:
    new_content = []
    for block in response.content:
        if block.type == "text":
            result = scan_and_redact(block.text, engine=config.engine)
            mapper.store(result.mapping)  # persist for round-trip
            new_content.append(TextContent(text=result.redacted_text))
        else:
            new_content.append(block)  # pass through images, etc.
    return CallToolResult(content=new_content)
```

**2. Tool Call Arguments (inbound — round-trip)**

When the agent sends a `tools/call` request to the target server, scan the arguments for DataFog tokens (e.g., `[EMAIL_1]`). If found, restore the real values from the mapper before forwarding to the target server.

```python
async def intercept_tool_call(request: CallToolRequest) -> CallToolRequest:
    restored_args = {}
    for key, value in request.arguments.items():
        if isinstance(value, str):
            restored_args[key] = mapper.restore(value)
        else:
            restored_args[key] = value
    return CallToolRequest(name=request.name, arguments=restored_args)
```

This is the bidirectional mapping that makes the proxy transparent. The agent works with tokens, the target server works with real values, neither knows the other exists.

**3. Resource Content (outbound — optional, phase 2)**

When the agent reads a `resource://` URI, scan the returned content for PII. Same logic as tool responses.

### Token Mapper (`mapper.py`)

The mapper maintains a bidirectional mapping for the duration of the proxy session.

```python
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class TokenMapper:
    """Bidirectional PII token ↔ real value mapping for a proxy session."""

    _token_to_real: dict[str, str] = field(default_factory=dict)
    _real_to_token: dict[str, str] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def store(self, mapping: dict[str, str]) -> None:
        """Store a mapping from a redaction result. mapping: {token: real_value}"""
        with self._lock:
            for token, real in mapping.items():
                self._token_to_real[token] = real
                self._real_to_token[real] = token

    def restore(self, text: str) -> str:
        """Replace any tokens in text with their real values."""
        with self._lock:
            for token, real in sorted(
                self._token_to_real.items(), key=lambda x: len(x[0]), reverse=True
            ):
                text = text.replace(token, real)
        return text

    def redact(self, text: str) -> str:
        """Replace any known real values in text with their tokens."""
        with self._lock:
            for real, token in sorted(
                self._real_to_token.items(), key=lambda x: len(x[0]), reverse=True
            ):
                text = text.replace(real, token)
        return text

    @property
    def mapping_table(self) -> dict[str, str]:
        """Current token→real mapping (read-only copy)."""
        with self._lock:
            return dict(self._token_to_real)

    def clear(self) -> None:
        with self._lock:
            self._token_to_real.clear()
            self._real_to_token.clear()
```

### Proxy Implementation with FastMCP

FastMCP 2.0 has native proxy support. The approach: create a FastMCP server that proxies to the target, with hooks on tool call results.

```python
# src/datafog_mcp/proxy.py

import asyncio
import sys
from mcp.server.fastmcp import FastMCP
from fastmcp import Client
from datafog.engine import scan_and_redact
from .mapper import TokenMapper
from .config import ProxyConfig


async def run_proxy(config: ProxyConfig):
    """Run DataFog as an MCP proxy wrapping a target server."""

    mapper = TokenMapper()

    # Connect to the target server as a client
    # FastMCP Client can connect via stdio to a subprocess
    target_command = config.target_command  # e.g., "python3"
    target_args = config.target_args        # e.g., ["database-server.py"]

    # Create a proxy server that exposes the target's tools
    # but intercepts responses
    proxy = FastMCP(
        name=f"datafog-proxy({config.target_name})",
        version="0.1.0",
    )

    async with Client(
        command=target_command,
        args=target_args,
        env=config.target_env,
    ) as target:
        # List the target's tools and re-expose them through the proxy
        target_tools = await target.list_tools()

        for tool in target_tools:
            # Create a proxy handler for each tool
            # that forwards to the target, then intercepts the response
            _register_proxied_tool(proxy, target, tool, mapper, config)

        # Also proxy resources if the target has them
        target_resources = await target.list_resources()
        for resource in target_resources:
            _register_proxied_resource(proxy, target, resource, mapper, config)

        # Run the proxy server on stdio (facing the agent)
        proxy.run(transport="stdio")


def _register_proxied_tool(proxy, target, tool, mapper, config):
    """Register a proxy handler for a single target tool."""

    @proxy.tool(name=tool.name, description=tool.description)
    async def proxied_tool(**kwargs):
        # 1. Restore any tokens in the arguments
        restored_kwargs = {}
        for key, value in kwargs.items():
            if isinstance(value, str):
                restored_kwargs[key] = mapper.restore(value)
            else:
                restored_kwargs[key] = value

        # 2. Forward to target server
        result = await target.call_tool(tool.name, restored_kwargs)

        # 3. Intercept text content and scan for PII
        intercepted_parts = []
        for block in result.content:
            if hasattr(block, "text") and block.text:
                redaction = scan_and_redact(
                    text=block.text,
                    engine=config.engine,
                    entity_types=config.entity_types,
                    strategy=config.strategy,
                )
                if redaction.mapping:
                    mapper.store(redaction.mapping)
                intercepted_parts.append(redaction.redacted_text)
            else:
                intercepted_parts.append(str(block))

        return "\n".join(intercepted_parts)
```

**Note:** The exact FastMCP 2.0 proxy API may differ from this pseudocode. The implementation should follow FastMCP's actual proxy patterns (which may be cleaner than manually re-registering tools). The key architectural point is: intercept `CallToolResult` content, scan with `datafog.engine`, store mapping, return redacted text.

### Claude Desktop Config (Mode B)

```json
{
  "mcpServers": {
    "database-private": {
      "command": "uvx",
      "args": [
        "datafog-mcp", "proxy",
        "--wrap", "python3", "database-server.py",
        "--engine", "smart"
      ],
      "env": {
        "DATABASE_URL": "postgresql://localhost/mydb"
      }
    }
  }
}
```

User changes one line in their config: instead of pointing Claude at `python3 database-server.py`, they point it at `datafog-mcp proxy --wrap python3 database-server.py`. Everything else stays the same.

### Claude Code Config (Mode B)

```bash
# Before (unprotected):
claude mcp add database -- python3 database-server.py

# After (DataFog proxy):
claude mcp add database -- uvx datafog-mcp proxy --wrap python3 database-server.py
```

---

## CLI Interface

```bash
# Mode A: Run as tool server (default)
datafog-mcp
datafog-mcp serve
datafog-mcp serve --transport stdio          # default
datafog-mcp serve --transport streamable-http --port 8000

# Mode B: Run as proxy
datafog-mcp proxy --wrap <command> [args...]
datafog-mcp proxy --wrap python3 database-server.py
datafog-mcp proxy --wrap npx @modelcontextprotocol/server-postgres
datafog-mcp proxy --wrap node salesforce-server.js --engine regex --entities EMAIL,SSN

# Options (both modes):
#   --engine     Detection engine: regex|smart|gliner|spacy (default: smart)
#   --entities   Comma-separated entity types to detect (default: all)
#   --strategy   Redaction strategy: token|mask|hash (default: token)
#   --config     Path to datafog-mcp.toml config file
#   --verbose    Enable debug logging to stderr

# Utility:
datafog-mcp --version
datafog-mcp --help
```

### `__main__.py`

```python
# src/datafog_mcp/__main__.py

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="datafog-mcp",
        description="DataFog MCP Server — PII detection and redaction for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command", help="Mode")

    # Mode A: serve (default if no subcommand)
    serve_parser = subparsers.add_parser("serve", help="Run as MCP tool server")
    serve_parser.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http"])
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--engine", default="smart")
    serve_parser.add_argument("--config", default=None)
    serve_parser.add_argument("--verbose", action="store_true")

    # Mode B: proxy
    proxy_parser = subparsers.add_parser("proxy", help="Run as MCP proxy wrapping another server")
    proxy_parser.add_argument("--wrap", nargs=argparse.REMAINDER, required=True,
                              help="Command and args of the target MCP server to wrap")
    proxy_parser.add_argument("--engine", default="smart")
    proxy_parser.add_argument("--entities", default=None, help="Comma-separated entity types")
    proxy_parser.add_argument("--strategy", default="token", choices=["token", "mask", "hash"])
    proxy_parser.add_argument("--config", default=None)
    proxy_parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    # Default to serve mode if no subcommand
    if args.command is None or args.command == "serve":
        from .server import run_server
        run_server(transport=getattr(args, "transport", "stdio"))
    elif args.command == "proxy":
        from .proxy import run_proxy
        from .config import ProxyConfig
        config = ProxyConfig.from_args(args)
        import asyncio
        asyncio.run(run_proxy(config))


if __name__ == "__main__":
    main()
```

---

## Configuration

### Environment Variables

```bash
DATAFOG_ENGINE=smart           # Detection engine (default: smart)
DATAFOG_ENTITY_TYPES=          # Comma-separated, empty = all
DATAFOG_STRATEGY=token         # Redaction strategy
DATAFOG_VERBOSE=0              # Debug logging
DATAFOG_NO_TELEMETRY=1         # Opt out of anonymous telemetry
```

### Config File (`datafog-mcp.toml`)

```toml
[server]
engine = "smart"
strategy = "token"
# entity_types = ["EMAIL", "SSN", "CREDIT_CARD"]  # uncomment to restrict

[proxy]
# Interception settings
intercept_tool_responses = true
intercept_tool_arguments = true     # restore tokens on the way back
intercept_resources = false         # off by default, enable for Mode B+
# log_redactions = true             # log what was redacted (to stderr)

[proxy.passthrough]
# Tool names that should NOT be scanned (e.g., math tools, code execution)
# Useful for performance — skip scanning tools that never return PII
tools = []
```

---

## pyproject.toml

```toml
[project]
name = "datafog-mcp"
version = "0.1.0"
description = "MCP server for PII detection and redaction — the privacy layer for AI agents"
readme = "README.md"
license = "MIT"
requires-python = ">=3.10"
authors = [{ name = "Sid Mohan", email = "hi@datafog.ai" }]
keywords = ["mcp", "pii", "privacy", "ai", "agents", "redaction"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Topic :: Security",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
]

dependencies = [
    "datafog>=4.3.0",
    "mcp>=1.2.0",
    "fastmcp>=2.14,<3",
]

[project.scripts]
datafog-mcp = "datafog_mcp.__main__:main"

[project.urls]
Homepage = "https://datafog.ai"
Repository = "https://github.com/DataFog/datafog-mcp"
Documentation = "https://docs.datafog.ai/mcp"
```

---

## Build Phases

### Phase 1: Mode A Tool Server (ship in ~3 days)

- [ ] Scaffold repo with pyproject.toml, src layout
- [ ] Implement `server.py` with `datafog_scan`, `datafog_redact`, `datafog_restore` tools
- [ ] Implement `__main__.py` CLI with `serve` subcommand
- [ ] Test with Claude Desktop (stdio) and MCP Inspector
- [ ] Test with Claude Code (`claude mcp add`)
- [ ] Write README with install + config instructions
- [ ] Publish to PyPI as `datafog-mcp` 0.1.0

### Phase 2: Token Mapper + Proxy Foundation (~1 week)

- [ ] Implement `mapper.py` with bidirectional token↔value mapping
- [ ] Unit tests for mapper (store, restore, redact, concurrent access, clear)
- [ ] Implement `interceptor.py` — the scan-and-replace logic for tool responses
- [ ] Test interceptor with mock tool responses containing various PII patterns

### Phase 3: Mode B Proxy (~1 week after Phase 2)

- [ ] Implement `proxy.py` using FastMCP proxy patterns
- [ ] Handle subprocess lifecycle (launch target, forward stdio, clean shutdown)
- [ ] Implement argument restoration (tokens → real values on tool calls going to target)
- [ ] Add `--wrap` CLI support
- [ ] Integration test: proxy wrapping a simple test MCP server
- [ ] Integration test: proxy wrapping `@modelcontextprotocol/server-filesystem`
- [ ] Integration test: round-trip — agent gets redacted data, sends token back, target gets real value
- [ ] Test with Claude Desktop config
- [ ] Publish 0.2.0

### Phase 4: Polish (~1 week after Phase 3)

- [ ] Config file support (datafog-mcp.toml)
- [ ] Passthrough list (skip scanning for specified tools)
- [ ] Redaction logging (to stderr, opt-in)
- [ ] Telemetry (same anonymous PostHog pattern as datafog-python)
- [ ] Resource interception (Mode B+)
- [ ] Performance benchmarks: latency added per tool call at various text sizes
- [ ] README with architecture diagrams, config reference, Claude Desktop/Code examples
- [ ] Publish 0.3.0 or 1.0.0

---

## Key Design Decisions

### Why FastMCP 2.x (not just raw `mcp` SDK)?

FastMCP 2.0 provides proxy support, transport bridging, and a cleaner tool registration API. The raw `mcp` SDK would require manually implementing JSON-RPC routing for the proxy pattern. Pin to `fastmcp>=2.14,<3` since 3.0 is in RC with potential breaking changes.

### Why subprocess wrapper (not HTTP gateway)?

The subprocess pattern (launch target as child process, proxy stdio) is simpler, works with any stdio MCP server (which is the vast majority), and requires the user to change only one line in their Claude config. An HTTP gateway (standalone service, SSE/Streamable HTTP) is the enterprise pattern — save for later.

### Why synchronous engine calls?

`datafog.engine.scan()` is synchronous and CPU-bound (regex + optional ML inference). The MCP proxy is async (reading/writing stdio streams). We call the engine via `asyncio.to_thread(scan, ...)` to avoid blocking the event loop. This is correct because:

1. The engine is CPU-bound, not I/O-bound — `to_thread` puts it in a thread pool
2. No event loop conflicts (unlike `asyncio.run()` inside an existing loop)
3. The thread pool is bounded, providing natural backpressure

```python
import asyncio
from datafog.engine import scan_and_redact

async def intercept(text: str, config) -> RedactResult:
    return await asyncio.to_thread(
        scan_and_redact,
        text=text,
        engine=config.engine,
        entity_types=config.entity_types,
        strategy=config.strategy,
    )
```

### Why token-based redaction (not pseudonymization)?

mcp-server-conceal does pseudonymization (replaces `john@acme.com` with `mike@techcorp.com`). This preserves semantic structure but is harder to implement correctly and can confuse agents (they might act on the fake data as if it's real). Token-based redaction (`[EMAIL_1]`) is:

1. Unambiguous — the agent knows it's a placeholder
2. Reversible — simple string replacement from the mapping table
3. Type-informative — the agent can reason about "there's an email here" without seeing it

Pseudonymization can be added as `strategy="pseudonymize"` later if there's demand.

### What about streaming?

MCP tool responses are not streamed (they're complete JSON-RPC responses). So there's no streaming interception concern for Mode B. If MCP adds streaming tool responses in the future, the interceptor would need to buffer until a complete text segment is available before scanning.
