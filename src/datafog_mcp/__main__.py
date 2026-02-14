from __future__ import annotations

import argparse
import asyncio

from . import __version__
from .server import run_server
from .config import ProxyConfig


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="datafog-mcp",
        description="DataFog MCP Server — PII detection and redaction for AI agents",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Mode")

    serve_parser = subparsers.add_parser("serve", help="Run as MCP tool server")
    serve_parser.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http"])
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--engine", default="smart")
    serve_parser.add_argument("--config", default=None)
    serve_parser.add_argument("--verbose", action="store_true")

    proxy_parser = subparsers.add_parser("proxy", help="Run as MCP proxy wrapping another server")
    proxy_parser.add_argument(
        "--wrap",
        nargs=argparse.REMAINDER,
        required=True,
        help="Command and args of the target MCP server to wrap",
    )
    proxy_parser.add_argument("--engine", default="smart")
    proxy_parser.add_argument("--entities", default=None, help="Comma-separated entity types")
    proxy_parser.add_argument("--strategy", default="token", choices=["token", "mask", "hash"])
    proxy_parser.add_argument("--config", default=None)
    proxy_parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.command in (None, "serve"):
        run_server(transport=getattr(args, "transport", "stdio"))
        return

    if args.command == "proxy":
        from .proxy import run_proxy

        config = ProxyConfig.from_args(args)
        asyncio.run(run_proxy(config))


if __name__ == "__main__":
    main()
