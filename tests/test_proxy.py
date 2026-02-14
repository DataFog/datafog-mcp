from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP
from fastmcp import Client

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

    async def fake_scan_and_replace_text(text: str, _mapper: TokenMapper, _config: object) -> str:
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
