# datafog-mcp

Python MCP server for local PII detection and redaction.

## What’s included

- Mode A: MCP tool server with `datafog_scan`, `datafog_redact`, and `datafog_restore`.
- CLI entrypoint: `datafog-mcp` and `python -m datafog_mcp`.
- Proxy mode scaffold in place (next phase).

## Install

```bash
pip install -e .
```

## Run

```bash
datafog-mcp
# or
datafog-mcp serve --transport stdio
```

## Dependencies

Starts from `datafog==4.3.0`.
