"""
Wraps a target server and governs its responses.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP


def build_proxy(command: str, args: list[str]) -> FastMCP[Any]:
    """
    Build a proxy in front of a stdio MCP server.

    Parameters:
      command: Executable that starts the target server.
      args: Arguments passed to that executable.
    Returns:
      A proxy exposing the target's capabilities.
    """
    config: dict[str, Any] = {
        "mcpServers": {
            "target": {
                "command": command,
                "args": args,
                "transport": "stdio",
            }
        }
    }
    return FastMCP.as_proxy(config, name="datafog-proxy")


def run_proxy(command: str, args: list[str]) -> None:
    """
    Run the proxy on stdio until the client disconnects.

    Parameters:
      command: Executable that starts the target server.
      args: Arguments passed to that executable.
    Returns:
      None.
    """
    build_proxy(command, args).run(transport="stdio")
