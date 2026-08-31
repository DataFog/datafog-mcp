"""
CLI entry point for datafog-mcp.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__

if TYPE_CHECKING:
    from fastmcp.server.middleware import Middleware


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
    adopt = sub.add_parser("adopt", help="Move registered MCP servers behind the proxy")
    adopt.add_argument("--config", metavar="PATH", default=None)
    adopt.add_argument("--executable", metavar="PATH", default=None)
    adopt.add_argument("--strategy", choices=("mask", "token"), default="mask")
    adopt.add_argument("--skip-keys", metavar="KEYS", default="")
    adopt.add_argument("--dry-run", action="store_true")
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
    proxy.add_argument(
        "--strategy",
        choices=("mask", "token"),
        default="mask",
        help="How to replace detections (default: mask)",
    )
    proxy.add_argument(
        "--skip-keys",
        metavar="KEYS",
        default="",
        help="Comma-separated payload keys to leave unscanned",
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


def _middleware_from_args(args: argparse.Namespace) -> Middleware:
    """
    Build the redacting middleware from command-line arguments.

    Parameters:
      args: Parsed command-line arguments.
    Returns:
      Middleware applied to every proxied tool result.
    """
    from .middleware import RedactingMiddleware

    keys = frozenset(key.strip() for key in args.skip_keys.split(",") if key.strip())
    return RedactingMiddleware(strategy=args.strategy, skip_keys=keys)


def _configure_logging() -> None:
    """
    Send log records to stderr.

    Under stdio transport stdout carries JSON-RPC, so a handler writing there
    corrupts the protocol stream.

    Returns:
      None
    """
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(message)s",
    )


def main() -> None:
    """
    Console entry point: `datafog-mcp`.
    """
    args = _build_parser().parse_args()

    if args.command == "adopt":
        from .adopt import DEFAULT_PROXY_CONFIG, AdoptError, adopt

        try:
            adopt(
                proxy_config=Path(args.config or DEFAULT_PROXY_CONFIG),
                executable=args.executable,
                strategy=args.strategy,
                skip_keys=args.skip_keys,
                dry_run=args.dry_run,
            )
        except AdoptError as exc:
            raise SystemExit(f"datafog-mcp: {exc}") from exc
        return

    if args.command == "proxy":
        from .proxy import ConfigError, run_proxy

        try:
            servers = _servers_from_args(args)
        except ConfigError as exc:
            raise SystemExit(f"datafog-mcp: {exc}") from exc
        _configure_logging()
        run_proxy(servers, _middleware_from_args(args))
        return

    from .server import run_server

    run_server()


if __name__ == "__main__":
    main()
