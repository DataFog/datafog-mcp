"""
Smoke-test an installed datafog-mcp the way a user's MCP client runs it.

The release workflow installs the built wheel into a clean environment outside
the checkout and runs this with that environment's interpreter. It exercises
the real console script over stdio, so it tests what would be published rather
than the source tree.

Usage: python smoke_installed.py <expected-version>
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
from importlib.metadata import metadata
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

import datafog_mcp

SECRET = "jack.smith@example.com"
TOOLS = {
    "datafog_policy",
    "datafog_scan",
    "datafog_redact",
    "datafog_mask",
    "datafog_remove",
    "datafog_pseudonymize",
    "datafog_check_text",
}


def _require(condition: bool, message: str) -> None:
    """
    Stop the smoke test with a message when a check fails.

    Parameters:
      condition: The check that must hold.
      message: What went wrong, when it does not.
    """
    if not condition:
        sys.exit(f"smoke test failed: {message}")


def _check_installation(expected: str) -> str:
    """
    Check the package metadata, where it was imported from, and the CLI.

    Parameters:
      expected: The version being released.
    Returns:
      The path of the installed console script.
    """
    installed = metadata("datafog-mcp")
    _require(installed["Version"] == expected, f"metadata reports {installed['Version']}")
    _require(installed["License-Expression"] == "MIT", "license metadata missing or wrong")

    # A wheel installed outside the checkout lives under this interpreter's prefix
    source = Path(datafog_mcp.__file__).resolve()
    _require(Path(sys.prefix).resolve() in source.parents, f"imported from {source}")

    server = shutil.which("datafog-mcp", path=str(Path(sys.executable).parent))
    _require(server is not None, "console script datafog-mcp is not installed")
    assert server is not None

    printed = subprocess.run([server, "--version"], capture_output=True, text=True, check=True)
    _require(printed.stdout.strip() == f"datafog-mcp {expected}", f"--version: {printed.stdout!r}")
    return server


async def _check_session(server: str, workdir: Path, expected: str) -> None:
    """
    Drive one stdio session through the scan and redact tools.

    Parameters:
      server: The installed console script.
      workdir: A scratch directory used as the only allowed root.
      expected: The version being released.
    """
    source = workdir / "contacts.csv"
    source.write_text(f"name,email\nJack,{SECRET}\n", encoding="utf-8")
    env = {
        **os.environ,
        "DATAFOG_MCP_ALLOWED_ROOTS": str(workdir),
        "FASTMCP_HOME": str(workdir / "fastmcp"),
    }

    async with Client(StdioTransport(server, [], env=env, cwd=str(workdir))) as client:
        handshake = client.initialize_result
        _require(handshake is not None, "handshake did not complete")
        assert handshake is not None
        _require(handshake.serverInfo.version == expected, "handshake reports the wrong version")

        names = {tool.name for tool in await client.list_tools()}
        _require(names == TOOLS, f"tools listed: {sorted(names)}")

        scan = await client.call_tool("datafog_scan", {"path": str(source)})
        _require((scan.structured_content or {}).get("counts", {}).get("EMAIL") == 1, "EMAIL")
        _require(SECRET not in str(scan.structured_content), "scan returned the value")
        _require(SECRET not in str(scan.content), "scan content returned the value")

        draft = await client.call_tool("datafog_check_text", {"text": f"Contact {SECRET}"})
        _require((draft.structured_content or {}).get("counts") == {"EMAIL": 1}, "draft EMAIL")
        _require(SECRET not in str(draft.content), "draft check returned the value")
        _require(SECRET not in str(draft.structured_content), "draft data returned the value")
        _require(
            (draft.structured_content or {}).get("policy", {}).get("advisory") is True,
            "draft policy is not advisory",
        )

        redact = await client.call_tool("datafog_redact", {"path": str(source)})
        copy = Path((redact.structured_content or {})["output_path"])
        _require(SECRET not in copy.read_text(encoding="utf-8"), "value left in the copy")
        _require(SECRET in source.read_text(encoding="utf-8"), "the original was modified")


def main() -> None:
    """
    Run every check against the installed package.
    """
    _require(len(sys.argv) == 2, "usage: smoke_installed.py <expected-version>")
    expected = sys.argv[1]

    server = _check_installation(expected)
    with tempfile.TemporaryDirectory() as scratch:
        asyncio.run(_check_session(server, Path(scratch).resolve(), expected))

    print(f"smoke test passed for datafog-mcp {expected}")


if __name__ == "__main__":
    main()
