from __future__ import annotations

import asyncio
import keyword
import textwrap
from typing import Any

from mcp import types
from mcp.server.fastmcp import FastMCP
from fastmcp import Client

from .config import ProxyConfig
from .interceptor import (
    InterceptorConfig,
    is_candidate_text,
    is_resource_text,
    restore_object_payload,
    scan_and_replace_text,
)
from .mapper import TokenMapper


def _intercept_args(
    arguments: dict[str, Any] | None,
    mapper: TokenMapper,
    interceptor_config: InterceptorConfig,
) -> dict[str, Any]:
    if not arguments:
        return {}

    return {
        key: restore_object_payload(
            value,
            mapper,
            intercept_tool_arguments=interceptor_config.intercept_tool_arguments,
        )
        for key, value in arguments.items()
    }


async def _intercept_text_output(
    content: Any,
    mapper: TokenMapper,
    config: InterceptorConfig,
) -> Any:
    if not config.intercept_tool_responses:
        return content

    if isinstance(content, types.TextContent):
        if is_resource_text(content.text) and not config.intercept_resources:
            return content
        redacted = scan_and_replace_text(content.text, mapper, config)
        redacted_text = await redacted if asyncio.iscoroutine(redacted) else redacted
        return types.TextContent(
            type=content.type,
            text=redacted_text,
            annotations=content.annotations,
            meta=content.meta,
        )
    if isinstance(content, str):
        if is_resource_text(content) and not config.intercept_resources:
            return content
        if is_candidate_text(content):
            redacted = scan_and_replace_text(content, mapper, config)
            return await redacted if asyncio.iscoroutine(redacted) else redacted
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
    if hasattr(content, "model_dump"):
        dumped = content.model_dump()
        redacted_dump = await _intercept_text_output(dumped, mapper, config)
        try:
            return content.__class__(**redacted_dump)
        except (TypeError, ValueError):
            return redacted_dump
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
        intercept_tool_arguments=config.intercept_tool_arguments,
        intercept_tool_responses=config.intercept_tool_responses,
        intercept_resources=config.intercept_resources,
    )

    def _is_valid_argument_name(name: str) -> bool:
        return name.isidentifier() and not keyword.iskeyword(name)

    def _build_tool_handler(tool_name: str, arg_names: list[str]) -> Any:
        params = ", ".join(f"{name}: Any = None" for name in arg_names)
        args_dict = ", ".join(f'"{name}": {name}' for name in arg_names)
        args_expr = f"{{{args_dict}}}"
        handler_source = textwrap.dedent(
            f"""\
            async def _tool_handler({params}) -> Any:
                restored = _intercept_args(
                    {args_expr},
                    mapper,
                    interceptor_config,
                )
                call_result: Any = await client.call_tool(_tool_name, restored)

                content = None
                if call_result.content is not None:
                    content = [
                        await _intercept_text_output(item, mapper, interceptor_config)
                        for item in call_result.content
                    ]

                structured_content = getattr(call_result, "structured_content", None)
                if structured_content is None:
                    structured_content = getattr(call_result, "structuredContent", None)
                if structured_content is not None:
                    structured_content = await _intercept_text_output(
                        structured_content,
                        mapper,
                        interceptor_config,
                    )

                is_error = getattr(call_result, "isError", False)
                is_error = getattr(call_result, "is_error", is_error)

                if is_error:
                    return content or ""

                if structured_content is not None:
                    if content is None:
                        return structured_content

                if content is not None:
                    if len(content) == 1 and isinstance(content[0], types.TextContent):
                        return content[0].text
                    return content
                return ""
            """
        )
        namespace = {
            "Any": Any,
            "client": client,
            "mapper": mapper,
            "interceptor_config": interceptor_config,
            "types": types,
            "_intercept_args": _intercept_args,
            "_intercept_text_output": _intercept_text_output,
            "_tool_name": tool_name,
        }
        exec(handler_source, namespace)
        return namespace["_tool_handler"]

    for tool in tools:
        input_properties = (tool.inputSchema or {}).get("properties", {})
        property_names = list(input_properties.keys())

        if not all(_is_valid_argument_name(name) for name in property_names):
            raise ValueError(
                f"Unsupported tool argument names for proxying: {tool.name}",
            )

        tool_handler = _build_tool_handler(tool.name, property_names)
        proxy.tool(
            name=tool.name,
            title=tool.title or tool.name,
            description=tool.description,
        )(tool_handler)


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
