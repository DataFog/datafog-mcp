from __future__ import annotations

import asyncio
import contextlib
import json
import keyword
import textwrap
from typing import Any

from fastmcp import Client
from mcp import types
from mcp.server.fastmcp import FastMCP

from .config import ProxyConfig
from .interceptor import (
    InterceptorConfig,
    is_candidate_text,
    is_resource_text,
    restore_object_payload,
    scan_and_replace_text,
)
from .mapper import TokenMapper

_TARGET_CONNECT_ATTEMPTS = 3
_TARGET_CONNECT_BASE_DELAY_SECONDS = 0.2


def _build_target_transport(config: ProxyConfig) -> dict[str, Any]:
    target_args = [config.target_command, *(config.target_args or [])]
    return {
        "mcpServers": {
            "target": {
                "command": target_args[0],
                "args": target_args[1:],
                "transport": "stdio",
            },
        },
    }


async def _acquire_target_client(target_transport: dict[str, Any]) -> Client:
    last_error: Exception | None = None

    for attempt in range(1, _TARGET_CONNECT_ATTEMPTS + 1):
        target_client = Client(target_transport)

        try:
            await target_client.__aenter__()
        except Exception as exc:
            with contextlib.suppress(Exception):
                await target_client.close()
            last_error = exc

            if attempt >= _TARGET_CONNECT_ATTEMPTS:
                break

            delay = _TARGET_CONNECT_BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            await asyncio.sleep(delay)
            continue

        return target_client

    raise RuntimeError(
        "Failed to connect to target MCP server. "
        "Check that the command in --wrap is valid and reachable.",
    ) from last_error


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
        text_content = await _intercept_text_output(content.text, mapper, config)
        text = text_content if isinstance(text_content, str) else str(text_content)
        return types.TextContent(
            type=content.type,
            text=text,
            annotations=content.annotations,
            meta=content.meta,
        )
    if isinstance(content, str):
        if is_resource_text(content) and not config.intercept_resources:
            return content
        if is_candidate_text(content):
            normalized = content.strip()
            if (
                normalized.startswith("{")
                and normalized.endswith("}")
                or normalized.startswith("[")
                and normalized.endswith("]")
            ) and not config.intercept_resources:
                try:
                    parsed = json.loads(content)
                    return json.dumps(
                        await _intercept_text_output(parsed, mapper, config),
                    )
                except (TypeError, ValueError):
                    pass
            redacted = scan_and_replace_text(content, mapper, config)
            return await redacted if asyncio.iscoroutine(redacted) else redacted
        return content
    if isinstance(content, list):
        return [
            item
            if isinstance(item, str) and is_resource_text(item) and not config.intercept_resources
            else await _intercept_text_output(item, mapper, config)
            for item in content
        ]
    if isinstance(content, dict):
        return {
            key: value
            if isinstance(value, str) and is_resource_text(value) and not config.intercept_resources
            else await _intercept_text_output(value, mapper, config)
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
                try:
                    call_result: Any = await client.call_tool(_tool_name, restored)
                except Exception as exc:
                    return "Upstream tool call failed: " + str(exc)

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

    target_transport = _build_target_transport(config)

    mapper = TokenMapper()
    proxy = FastMCP(name="datafog-proxy")

    target_client = await _acquire_target_client(target_transport)
    try:
        target_tools = await target_client.list_tools()
        await _register_proxied_tools(
            proxy,
            target_client,
            target_tools,
            mapper,
            config,
        )
        await proxy.run_stdio_async()
    finally:
        await target_client.__aexit__(None, None, None)


def run_proxy_sync(config: ProxyConfig) -> None:
    asyncio.run(run_proxy(config))
