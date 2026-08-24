"""
CLI entry point for the datafog-mcp scan server.
"""

from __future__ import annotations

from . import __version__
from .server import run_server


def main() -> None:
    """
    Console entry point: `datafog-mcp`.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="datafog-mcp",
        description="DataFog MCP scan server - local PII detection for AI agents",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args()
    run_server()


if __name__ == "__main__":
    main()
