"""Tests for the file size limit, through the MCP server."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.config import DEFAULT_MAX_BYTES
from datafog_mcp.server import mcp


def _scan(path: Path) -> dict[str, Any]:
    """
    Scan a file through an in-memory MCP client.

    Parameters:
      path: The file to scan.
    Returns:
      The tool's structured result.
    """

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool("datafog_scan", {"path": str(path)})
            return result.structured_content or {}

    return asyncio.run(run())


def _sized_file(tmp_path: Path, size: int) -> Path:
    """
    Write a text file of an exact size, ending with one email address.

    Parameters:
      tmp_path: Directory for the file.
      size: Total size in bytes.
    Returns:
      The file's path.
    """
    tail = "user@example.com\n"
    path = tmp_path / "large.log"
    path.write_text("x" * (size - len(tail) - 1) + "\n" + tail, encoding="utf-8")
    assert path.stat().st_size == size
    return path


def test_limit_is_ten_decimal_megabytes() -> None:
    """The limit is 10 MB in decimal units, as the benchmarks measured."""
    assert DEFAULT_MAX_BYTES == 10_000_000


def test_file_at_the_limit_is_scanned(tmp_path: Path) -> None:
    """
    A file of exactly the limit is scanned in full, to its last line.

    Parameters:
      tmp_path: Directory for the input.
    """
    result = _scan(_sized_file(tmp_path, DEFAULT_MAX_BYTES))

    assert result["counts"] == {"EMAIL": 1}


def test_file_over_the_limit_is_refused(tmp_path: Path) -> None:
    """
    One byte over the limit is refused, never scanned in part.

    Parameters:
      tmp_path: Directory for the input.
    """
    with pytest.raises(ToolError, match="limit"):
        _scan(_sized_file(tmp_path, DEFAULT_MAX_BYTES + 1))
