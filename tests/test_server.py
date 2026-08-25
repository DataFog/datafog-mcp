"""End-to-end tests for the datafog_scan tool."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.server import mcp

DATA = Path(__file__).parent / "data" / "garmin_export.csv"


def _call(**arguments: Any) -> dict[str, Any]:
    """
    Invoke datafog_scan through an in-memory MCP client.

    Parameters:
      arguments: Tool arguments forwarded to datafog_scan.
    Returns:
      The tool's structured result.
    """

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool("datafog_scan", arguments)
            return result.structured_content or {}

    return asyncio.run(run())


def test_finds_profile_identifiers() -> None:
    """The header block's email, phone, and postal code are found."""
    result = _call(path=str(DATA))
    values = {e["value"] for e in result["entities"]}

    assert "jack.smith@example.com" in values
    assert "415-555-0182" in values
    assert "94117" in values
    assert result["engine_used"] == "regex"


def test_does_not_return_file_contents() -> None:
    """
    Only matched substrings come back, never the file itself.

    This is what makes path-based scanning worth doing: the agent
    learns what is in the file without the file entering context.
    """
    payload = json.dumps(_call(path=str(DATA)))

    for unmatched in ["cycling", "swimming", "avg_hr", "28.4"]:
        assert unmatched not in payload


def test_date_over_matches_activity_dates() -> None:
    """
    Activity dates register as DATE alongside the real birth date.

    Documents a known precision gap. Suppressing it needs
    allowlist_patterns, which is not wired up yet.
    """
    result = _call(path=str(DATA))
    dates = [e["value"] for e in result["entities"] if e["type"] == "DATE"]

    assert "03/14/1987" in dates
    assert "2026-08-01" in dates
    assert len(dates) > 1


def test_missing_file_reports_tool_error() -> None:
    """A nonexistent path surfaces as a tool error, not a crash."""
    with pytest.raises(ToolError):
        _call(path="/nonexistent/garmin.csv")


def test_binary_file_reports_tool_error(tmp_path: Path) -> None:
    """A ZIP is refused rather than scanned as decoded garbage."""
    archive = tmp_path / "export.zip"
    archive.write_bytes(b"PK\x03\x04\x00\x00archive body")

    with pytest.raises(ToolError):
        _call(path=str(archive))


def test_unimplemented_mode_reports_tool_error() -> None:
    """summary is declared but not built, and says so."""
    with pytest.raises(ToolError):
        _call(path=str(DATA), mode="summary")
