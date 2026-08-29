"""
Wraps target servers and governs their responses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastmcp import FastMCP


class ConfigError(ValueError):
    """The server config file is missing or malformed."""


def load_servers(path: str) -> dict[str, Any]:
    """
    Read an MCP server map from a JSON config file.

    Accepts the standard MCP client format, so an existing mcp.json or
    claude_desktop_config.json can be pointed at directly.

    Parameters:
      path: The path to a JSON file holding an "mcpServers" object.
    Returns:
      The mcpServers mapping, name to server config.
    """
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise ConfigError(f"no such config file: {resolved}")

    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{resolved} is not valid JSON: {exc}") from exc

    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        raise ConfigError(f"{resolved} has no non-empty 'mcpServers' object")

    return servers


def build_proxy(servers: dict[str, Any]) -> FastMCP[Any]:
    """
    Build one proxy in front of every configured server.

    Parameters:
      servers: An mcpServers mapping, name to server config.
    Returns:
      A proxy exposing every target's capabilities.
    """
    return FastMCP.as_proxy({"mcpServers": servers}, name="datafog-proxy")


def run_proxy(servers: dict[str, Any]) -> None:
    """
    Run the proxy on stdio until the client disconnects.

    Parameters:
      servers: An mcpServers mapping, name to server config.
    Returns:
      None.
    """
    build_proxy(servers).run(transport="stdio")
