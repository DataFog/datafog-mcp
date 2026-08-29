"""
CLI entry point for datafog-mcp.
"""

from __future__ import annotations

import argparse

from . import __version__


def _build_parser() -> argparse.ArgumentParser:
    """
    Construct the argument parser.

    Parameters:
      None
    Returns:
      A parser carrying the serve and proxy subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="datafog-mcp",
        description="Local PII detection for MCP clients",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("serve", help="Run the scan tool server (default)")

    proxy = sub.add_parser("proxy", help="Wrap other MCP servers")
    source = proxy.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--config",
        metavar="PATH",
        help="JSON file containing an mcpServers object",
    )
    source.add_argument(
        "--wrap",
        nargs=argparse.REMAINDER,
        metavar="COMMAND",
        help="Command and arguments of a single target server",
    )
    return parser


def _servers_from_args(args: argparse.Namespace) -> dict[str, object]:
    """
    Resolve the server map from either --config or --wrap.

    Parameters:
      args: Parsed command-line arguments.
    Returns:
      An mcpServers mapping, name to server config.
    """
    from .proxy import load_servers

    if args.config:
        return load_servers(args.config)

    wrap: list[str] = args.wrap
    if not wrap:
        raise SystemExit("--wrap requires a command")
    return {
        "target": {
            "command": wrap[0],
            "args": wrap[1:],
            "transport": "stdio",
        }
    }


def main() -> None:
    """
    Console entry point: `datafog-mcp`.
    """
    args = _build_parser().parse_args()

    if args.command == "proxy":
        from .proxy import ConfigError, run_proxy

        try:
            servers = _servers_from_args(args)
        except ConfigError as exc:
            raise SystemExit(f"datafog-mcp: {exc}") from exc
        run_proxy(servers)
        return

    from .server import run_server

    run_server()


if __name__ == "__main__":
    main()
