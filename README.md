# datafog-mcp

`datafog-mcp` is a Python MCP server that adds local PII scan and redaction tooling for AI agents.

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended package manager)

## Install and run

Use `uv` as the primary developer/deployment workflow.

```bash
# bootstrap editable install with dev dependencies
uv sync --group dev

# run the MCP server
uv run datafog-mcp
# or explicit
uv run datafog-mcp serve --transport stdio
# streamable-http transport
uv run datafog-mcp serve --transport streamable-http --port 8000
```

## Dependency baseline

The project starts with `datafog==4.3.0`.

## Runtime configuration

Mode A reads configuration from (in precedence order):
1) CLI arguments
2) `DATAFOG_*` env vars
3) `datafog-mcp.toml` if present

Supported values:

- `DATAFOG_ENGINE`
- `DATAFOG_ENTITY_TYPES`
- `DATAFOG_STRATEGY`
- `DATAFOG_VERBOSE`
- `DATAFOG_NO_TELEMETRY`

`datafog-mcp.toml` also supports `engine` and `strategy` under `[server]`.

## Development workflow

### Setup

```bash
uv sync --group dev --group docs
uv run pre-commit install
```

### Code quality

```bash
uv run ruff check .
uv run ruff format .
uv run mypy
uv run pyright
uv run pytest
```

### Pre-commit

```bash
pre-commit run --all-files
```

## Documentation

```bash
uv run mkdocs serve
```

Then open <http://127.0.0.1:8000>.

## Repository layout

```text
datafog-mcp/
├── src/datafog_mcp/
│   ├── __init__.py
│   ├── __main__.py
│   ├── config.py
│   ├── proxy.py
│   ├── server.py
├── tests/
├── docs/
├── datafog-mcp.toml
├── pyproject.toml
├── README.md
├── ROADMAP.md
```

## Roadmap and spec

See `ROADMAP.md` for implementation tracking against the product spec.
