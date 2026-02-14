from __future__ import annotations

import asyncio
from typing import Any

from mcp import types
from mcp.server.fastmcp import FastMCP
from fastmcp import Client

from .config import ProxyConfig
from .interceptor import (
    InterceptorConfig,
    is_candidate_text,
    restore_object_payload,
    scan_and_replace_text,
)
from .mapper import TokenMapper


def _intercept_args(arguments: dict[str, Any] | None, mapper: TokenMapper) -> dict[str, Any]:
    if not arguments:
        return {}

    return {
        key: restore_object_payload(value, mapper) for key, value in arguments.items()
    }


async def _intercept_text_output(
    content: Any,
    mapper: TokenMapper,
    config: InterceptorConfig,
) -> Any:
    if isinstance(content, types.TextContent):
        redacted_text = await scan_and_replace_text(content.text, mapper, config)
        return types.TextContent(
            type=content.type,
            text=redacted_text,
            annotations=content.annotations,
            meta=content.meta,
        )
    if isinstance(content, str):
        if is_candidate_text(content):
            return await scan_and_replace_text(content, mapper, config)
        return content
    if isinstance(content, list):
        return [
            await _intercept_text_output(item, mapper, config) for item in content
        ]
    if isinstance(content, dict):
        return {
            key: await _intercept_text_output(value, mapper, config)
            for key, value in content.items()
        }
    return content


async def _register_proxied_tools(
    proxy: FastMCP,
    client: Client,
    tools: list[types.Tool],
    mapper: TokenMapper,
    config: ProxyConfig,
) -> None:
    interceptor_config = InterceptorConfig(
        engine=config.engine,
        entity_types=config.entity_types,
        strategy=config.strategy,
    )

    for tool in tools:
        async def _tool_handler(**kwargs: Any, _tool_name: str = tool.name) -> Any:
            restored = _intercept_args(kwargs, mapper)
            result: Any = await client.call_tool(_tool_name, restored)
            if result.content is not None:
                result.content = [
                    await _intercept_text_output(item, mapper, interceptor_config)
                    for item in result.content
                ]
            if result.structuredContent is not None:
                result.structuredContent = await _intercept_text_output(
                    result.structuredContent,
                    mapper,
                    interceptor_config,
                )
            return result

        proxy.tool(
            name=tool.name,
            title=tool.title or tool.name,
            description=tool.description,
        )(_tool_handler)


async def run_proxy(config: ProxyConfig) -> None:
    """Run datafog-mcp as a proxy with transparent redact-and-restore flow."""

    target_command = config.target_command
    if not target_command:
        raise ValueError("Proxy mode requires --wrap <command> [args...]")

    target_args = [target_command, *(config.target_args or [])]
    target_transport = {
        "mcpServers": {
            "target": {
                "command": target_args[0],
                "args": target_args[1:],
                "transport": "stdio",
            },
        },
    }

    mapper = TokenMapper()
    target_client = Client(target_transport)
    proxy = FastMCP(name="datafog-proxy")

    async with target_client:
        target_tools = await target_client.list_tools()
        await _register_proxied_tools(
            proxy,
            target_client,
            target_tools,
            mapper,
            config,
        )
        await proxy.run_stdio_async()


def run_proxy_sync(config: ProxyConfig) -> None:
    asyncio.run(run_proxy(config))
