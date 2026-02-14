from __future__ import annotations

import asyncio

from .config import ProxyConfig


async def run_proxy(config: ProxyConfig) -> None:
    """Run as an MCP proxy wrapping a target server.

    This scaffold provides argument parsing and process wiring for the next
    implementation phase.
    """

    raise NotImplementedError(
        "Proxy mode scaffold created. Implement tool/resource interception in Phase 2."
    )


def run_proxy_sync(config: ProxyConfig) -> None:
    asyncio.run(run_proxy(config))
