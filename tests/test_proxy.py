from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from fastmcp import Client
from mcp.server.fastmcp import FastMCP

import datafog_mcp.proxy as proxy_module
from datafog_mcp.config import ProxyConfig
from datafog_mcp.mapper import TokenMapper
from datafog_mcp.proxy import _register_proxied_tools


def test_proxy_restores_nested_args_and_redacts_text_output(monkeypatch: object) -> None:
    target = FastMCP(name="target-server")
    observed: dict[str, object] = {}

    @target.tool()
    def nested_tool(payload: dict[str, object]) -> str:
        observed["payload"] = payload
        return f"payload={payload}"

    def fake_scan_and_replace_text(text: str, _mapper: TokenMapper, _config: object) -> str:
        return text.replace("alice@example.com", "[EMAIL_1]")

    async def run() -> None:
        mapper = TokenMapper()
        mapper.store({"[EMAIL_1]": "alice@example.com"})

        proxy = FastMCP(name="datafog-proxy")
        async with Client(target) as target_client:
            target_tools = await target_client.list_tools()
            await _register_proxied_tools(
                proxy=proxy,
                client=target_client,
                tools=target_tools,
                mapper=mapper,
                config=ProxyConfig(
                    target_command="python",
                    target_args=["-c", "pass"],
                ),
            )

            async with Client(proxy) as proxy_client:
                tools = await proxy_client.list_tools()
                tool_names = {tool.name for tool in tools}
                assert "nested_tool" in tool_names

                result = await proxy_client.call_tool(
                    "nested_tool",
                    {"payload": {"user": "[EMAIL_1]", "details": {"nested": True}}},
                )

                assert observed["payload"] == {
                    "user": "alice@example.com",
                    "details": {"nested": True},
                }

                assert result.content[0].text == (
                    "payload={'user': '[EMAIL_1]', 'details': {'nested': True}}"
                )

    monkeypatch.setattr(proxy_module, "scan_and_replace_text", fake_scan_and_replace_text)
    asyncio.run(run())


def test_proxy_resource_interception_toggle(monkeypatch: object) -> None:
    target = FastMCP(name="target-server")
    observed_resource = "https://api.example.com/user?email=alice@example.com"

    @target.tool()
    def resource_tool() -> dict:
        return {"uri": observed_resource}

    def fake_scan_and_replace_text(text: str, _mapper: TokenMapper, _config: object) -> str:
        return text.replace("alice@example.com", "[EMAIL_1]")

    async def run(with_resources: bool) -> dict[str, str]:
        async with Client(target) as target_client:
            target_tools = await target_client.list_tools()
            proxy = FastMCP(name="datafog-proxy")
            await _register_proxied_tools(
                proxy=proxy,
                client=target_client,
                tools=target_tools,
                mapper=TokenMapper(),
                config=ProxyConfig(
                    target_command="python",
                    target_args=["-c", "pass"],
                    intercept_tool_responses=True,
                    intercept_resources=with_resources,
                ),
            )

            async with Client(proxy) as proxy_client:
                result = await proxy_client.call_tool("resource_tool", {})
                return json.loads(result.content[0].text)

    monkeypatch.setattr(proxy_module, "scan_and_replace_text", fake_scan_and_replace_text)

    redacted = asyncio.run(run(with_resources=True))
    passthrough = asyncio.run(run(with_resources=False))

    assert redacted["uri"] == "https://api.example.com/user?email=[EMAIL_1]"
    assert passthrough["uri"] == observed_resource


def test_proxy_tool_call_failure_is_returned_as_text() -> None:
    target = FastMCP(name="target-server")

    @target.tool()
    def failing_tool() -> str:
        raise ValueError("boom")

    async def run() -> str:
        async with Client(target) as target_client:
            target_tools = await target_client.list_tools()
            proxy = FastMCP(name="datafog-proxy")
            await _register_proxied_tools(
                proxy=proxy,
                client=target_client,
                tools=target_tools,
                mapper=TokenMapper(),
                config=ProxyConfig(
                    target_command="python",
                    target_args=["-c", "pass"],
                ),
            )

            async with Client(proxy) as proxy_client:
                result = await proxy_client.call_tool("failing_tool", {})
                return result.content[0].text

    message = asyncio.run(run())
    assert "Upstream tool call failed" in message
    assert "boom" in message


def test_proxy_invalid_target_command_raises_readable_error(monkeypatch: object) -> None:
    monkeypatch.setattr(proxy_module, "_TARGET_CONNECT_ATTEMPTS", 1)

    async def run() -> None:
        await proxy_module.run_proxy(
            ProxyConfig(
                target_command="python-does-not-exist",
                target_args=["-c", "pass"],
            )
        )

    with pytest.raises(RuntimeError, match="Failed to connect to target MCP server"):
        asyncio.run(run())


def test_proxy_end_to_end_subprocess_target(tmp_path: Path) -> None:
    target_server = tmp_path / "target_server.py"
    records_path = tmp_path / "records.log"

    target_server.write_text(
        """\
from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP


def _append_record(value: str) -> None:
    path = sys.argv[1]
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(value + "\\n")


mcp = FastMCP(name=\"target-server\")


@mcp.tool()
def emit_email() -> str:
    return "alice@example.com"


@mcp.tool()
def record_payload(value: str) -> str:
    _append_record(value)
    return f\"received:{value}\"


@mcp.tool()
def resource_tool() -> dict[str, str]:
    return {\"uri\": \"https://api.example.com/user?email=alice@example.com\"}


if __name__ == \"__main__\":
    mcp.run(transport=\"stdio\")
""",
        encoding="utf-8",
    )

    records_path.write_text("", encoding="utf-8")

    proxy_transport = {
        "mcpServers": {
            "proxy": {
                "command": sys.executable,
                "args": [
                    "-m",
                    "datafog_mcp",
                    "proxy",
                    "--wrap",
                    sys.executable,
                    str(target_server),
                    str(records_path),
                ],
                "transport": "stdio",
            },
        },
    }

    async def run() -> tuple[str, str, str]:
        async with Client(proxy_transport) as proxy_client:
            first = await proxy_client.call_tool("emit_email", {})
            redacted_email = first.content[0].text

            restored = await proxy_client.call_tool(
                "record_payload",
                {"value": redacted_email},
            )

            resource = await proxy_client.call_tool("resource_tool", {})

            return (
                redacted_email,
                restored.content[0].text,
                resource.content[0].text,
            )

    redacted_email, restored_response, resource_response = asyncio.run(run())

    assert redacted_email == "[EMAIL_1]"
    assert restored_response == "received:[EMAIL_1]"
    records = records_path.read_text(encoding="utf-8").splitlines()
    assert records == ["alice@example.com"]

    payload = json.loads(resource_response)
    assert payload["uri"] == "https://api.example.com/user?email=alice@example.com"
