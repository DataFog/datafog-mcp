"""
Wraps target servers and governs their responses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from fastmcp.client.transports.config import MCPConfigTransport
from fastmcp.server import create_proxy
from fastmcp.server.middleware import Middleware


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


def build_proxy(
        servers: dict[str, Any],
        middleware: Middleware | None = None,
        ) -> FastMCP[Any]:
    """
    Build one proxy in front of every configured server.

    Parameters:
      servers: An mcpServers mapping, name to server config.
      middleware: Optional middleware applied to every request.
    Returns:
      A proxy exposing every target's capabilities.
    """
    transport = MCPConfigTransport({"mcpServers": servers}, name_as_prefix=False)
    proxy = create_proxy(transport, name="datafog-proxy")
    if middleware is not None:
        proxy.add_middleware(middleware)
    return proxy


def run_proxy(
        servers: dict[str, Any],
        middleware: Middleware | None = None,
        ) -> None:
    """
    Run the proxy on stdio until the client disconnects.

    Parameters:
      servers: An mcpServers mapping, name to server config.
      middleware: Optional middleware applied to every request.
    Returns:
      None.
    """
    build_proxy(servers, middleware).run(transport="stdio")
