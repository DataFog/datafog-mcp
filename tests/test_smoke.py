import asyncio
import json
import sys

from fastmcp import Client

from datafog_mcp import __version__


def test_package_version() -> None:
    assert isinstance(__version__, str)
    assert __version__.count(".") >= 1


def test_serve_runtime_smoke_via_fastmcp_client() -> None:
    server_transport = {
        "mcpServers": {
            "datafog-server": {
                "command": sys.executable,
                "args": [
                    "-m",
                    "datafog_mcp",
                    "serve",
                    "--no-telemetry",
                    "--log-redactions",
                ],
                "transport": "stdio",
            }
        }
    }

    async def run() -> str:
        async with Client(server_transport) as client:
            tools = await client.list_tools()
            names = {tool.name for tool in tools}
            assert "datafog_scan" in names
            assert "datafog_redact" in names
            assert "datafog_restore" in names

            result = await client.call_tool("datafog_redact", {"text": "hello alice@example.com"})
            return result.content[0].text

    response = asyncio.run(run())
    payload = json.loads(response)
    assert payload["redacted_text"] == "hello [EMAIL_1]"
