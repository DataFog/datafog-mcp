from __future__ import annotations

import argparse
import asyncio

from . import __version__
from .config import ProxyConfig, ServerConfig
from .server import run_server


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="datafog-mcp",
        description="DataFog MCP Server — PII detection and redaction for AI agents",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Mode")

    serve_parser = subparsers.add_parser("serve", help="Run as MCP tool server")
    serve_parser.add_argument("--transport", default=None, choices=["stdio", "streamable-http"])
    serve_parser.add_argument("--port", type=int, default=None)
    serve_parser.add_argument("--engine", default=None)
    serve_parser.add_argument("--entities", default=None, help="Comma-separated entity types")
    serve_parser.add_argument("--strategy", default=None, choices=["token", "mask", "hash"])
    serve_parser.add_argument("--config", default=None)
    serve_parser.add_argument("--verbose", action="store_true", default=None)
    serve_parser.add_argument(
        "--no-telemetry",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable datafog telemetry calls",
    )

    proxy_parser = subparsers.add_parser("proxy", help="Run as MCP proxy wrapping another server")
    proxy_parser.add_argument(
        "--wrap",
        nargs=argparse.REMAINDER,
        required=True,
        help="Command and args of the target MCP server to wrap",
    )
    proxy_parser.add_argument("--engine", default=None)
    proxy_parser.add_argument("--entities", default=None, help="Comma-separated entity types")
    proxy_parser.add_argument("--strategy", default=None, choices=["token", "mask", "hash"])
    proxy_parser.add_argument("--config", default=None)
    proxy_parser.add_argument("--verbose", action="store_true", default=None)
    proxy_parser.add_argument(
        "--no-telemetry",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable datafog telemetry calls",
    )
    proxy_parser.add_argument(
        "--intercept-tool-arguments",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable restoring tool arguments before forwarding to target",
    )
    proxy_parser.add_argument(
        "--intercept-tool-responses",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable redaction of proxied tool responses",
    )
    proxy_parser.add_argument(
        "--intercept-resources",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable resource/content interception in proxied responses",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.command in (None, "serve"):
        config = ServerConfig.from_args(args)
        run_server(transport=config.transport, config=config)
        return

    if args.command == "proxy":
        from .proxy import run_proxy

        config = ProxyConfig.from_args(args)
        asyncio.run(run_proxy(config))


if __name__ == "__main__":
    main()
