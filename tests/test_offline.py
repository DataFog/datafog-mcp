"""
The server makes no network requests while serving.

Runs the real entry point as a subprocess, the way an MCP client launches it,
with a network hook installed through sitecustomize. The hook records and
refuses any DNS lookup or connection to a non-loopback host.

The in-process tests elsewhere never call run(), so they cannot catch egress
that happens at startup, such as FastMCP's banner checking PyPI for updates.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from fastmcp.exceptions import ToolError

# Loaded by the child interpreter at startup. Records egress attempts to the
# file named by DATAFOG_EGRESS_LOG and refuses them. Loopback is allowed,
# since it never leaves the machine.
NETWORK_HOOK = """\
import os
import socket

_LOG = os.environ["DATAFOG_EGRESS_LOG"]
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}

with open(os.environ["DATAFOG_HOOK_MARKER"], "w", encoding="utf-8") as _marker:
    _marker.write("loaded")


def _refuse(kind, target):
    with open(_LOG, "a", encoding="utf-8") as handle:
        handle.write(f"{kind} {target!r}\\n")
    raise OSError(f"egress refused by test hook: {kind} {target!r}")


_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect


def _getaddrinfo(host, *args, **kwargs):
    if host not in _LOOPBACK:
        _refuse("resolve", host)
    return _real_getaddrinfo(host, *args, **kwargs)


def _connect(self, address):
    inet = self.family in (socket.AF_INET, socket.AF_INET6)
    if inet and address[0] not in _LOOPBACK:
        _refuse("connect", address)
    return _real_connect(self, address)


socket.getaddrinfo = _getaddrinfo
socket.socket.connect = _connect
"""


def test_serving_makes_no_network_requests(tmp_path: Path) -> None:
    """
    A full session over stdio attempts no DNS lookup or outbound connection.

    FastMCP's home directory starts empty, so there is no cached version and
    an update check would have to fetch one.

    Parameters:
      tmp_path: Holds the hook, its logs, FastMCP's home, and the input file.
    """
    hook_dir = tmp_path / "hook"
    hook_dir.mkdir()
    (hook_dir / "sitecustomize.py").write_text(NETWORK_HOOK, encoding="utf-8")

    egress_log = tmp_path / "egress.log"
    marker = tmp_path / "hook_loaded"
    stderr = tmp_path / "server-stderr.log"
    source = tmp_path / "contacts.csv"
    source.write_text("name,email\nJack,jack.smith@example.com\n", encoding="utf-8")

    python_path = os.pathsep.join(
        entry for entry in (str(hook_dir), os.environ.get("PYTHONPATH", "")) if entry
    )
    env = {
        **os.environ,
        "PYTHONPATH": python_path,
        "DATAFOG_EGRESS_LOG": str(egress_log),
        "DATAFOG_HOOK_MARKER": str(marker),
        "FASTMCP_HOME": str(tmp_path / "fastmcp-home"),
    }
    transport = StdioTransport(sys.executable, ["-m", "datafog_mcp"], env=env, log_file=stderr)

    async def session() -> None:
        async with Client(transport) as client:
            await client.call_tool("datafog_scan", {"path": str(source)})
            await client.call_tool("datafog_redact", {"path": str(source)})
            draft = "OUTBOUND_SENTINEL private-person@example.com"
            result = await client.call_tool("datafog_check_text", {"text": draft})
            assert (result.structured_content or {})["counts"] == {"EMAIL": 1}
            assert "OUTBOUND_SENTINEL" not in str(result.content)
            with pytest.raises(ToolError) as caught:
                await client.call_tool(
                    "datafog_check_text", {"text": draft, "entity_types": [draft]}
                )
            assert draft not in str(caught.value)

    asyncio.run(session())

    # Without this, a hook that failed to load would pass the test vacuously
    assert marker.read_text(encoding="utf-8") == "loaded"

    attempts = egress_log.read_text(encoding="utf-8") if egress_log.exists() else ""
    assert attempts == ""
    assert "OUTBOUND_SENTINEL" not in stderr.read_text(encoding="utf-8")
    assert "private-person@example.com" not in stderr.read_text(encoding="utf-8")
