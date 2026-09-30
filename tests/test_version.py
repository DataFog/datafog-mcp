"""
The version is declared once, in pyproject.toml, and reported consistently.

A release bumps pyproject.toml and the release workflow checks the tag
against it. Anything that reports a version must read it from there, or the
first release after 0.1.0 would ship a server announcing the wrong one.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest
from fastmcp import Client

import datafog_mcp
from datafog_mcp import __version__
from datafog_mcp.server import mcp

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_version() -> str:
    """
    Read the version pyproject.toml declares.

    A regex rather than tomllib, which Python 3.10 lacks.

    Returns:
      The [project] version string.
    """
    match = re.search(r'^version = "([^"]+)"$', PYPROJECT.read_text(encoding="utf-8"), re.M)
    assert match, "pyproject.toml declares no version"
    return match.group(1)


def test_package_version_is_the_declared_version() -> None:
    """
    __version__ matches pyproject.toml.

    A mismatch means either a stale install or a second, hardcoded source
    that has drifted.
    """
    assert __version__ == _declared_version()


def test_client_sees_the_package_version() -> None:
    """
    The MCP handshake reports the installed package's version.

    Clients read serverInfo to tell which release they are talking to.
    """

    async def handshake() -> str:
        async with Client(mcp) as client:
            result = client.initialize_result
            assert result is not None, "handshake did not complete"
            return result.serverInfo.version

    assert asyncio.run(handshake()) == version("datafog-mcp")


def test_uninstalled_source_reports_an_unknown_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Importing from a source tree that was never installed says so.

    There is no package metadata to read, and a guessed version would be
    wrong for every release after the one it was written for.

    Parameters:
      monkeypatch: Makes the metadata lookup fail as it does when uninstalled.
    """

    def uninstalled(name: str) -> str:
        """
        Fail the way importlib.metadata does for a package that isn't installed.

        Parameters:
          name: The distribution being looked up.
        Returns:
          Never returns.
        """
        raise PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", uninstalled)
    try:
        assert importlib.reload(datafog_mcp).__version__ == "0+unknown"
    finally:
        monkeypatch.undo()
        importlib.reload(datafog_mcp)
