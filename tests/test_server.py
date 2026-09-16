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

    assert result["counts"]["EMAIL"] == 1
    assert result["counts"]["PHONE"] == 1
    assert result["counts"]["ZIP_CODE"] == 1
    assert result["entity_count"] == sum(result["counts"].values())


def test_does_not_return_file_contents_or_matched_values() -> None:
    """
    Neither the file nor what was found in it comes back.

    This is what makes path-based scanning worth doing: the agent
    learns what is in the file without any of it entering context.
    """
    payload = json.dumps(_call(path=str(DATA)))

    for unmatched in ["cycling", "swimming", "avg_hr", "28.4"]:
        assert unmatched not in payload

    for matched in ["jack.smith@example.com", "415-555-0182", "94117"]:
        assert matched not in payload


def test_date_over_matches_activity_dates() -> None:
    """
    Activity dates register as DATE alongside the real birth date.

    Documents a known precision gap: the file holds one date of birth
    and several activity dates, and nothing distinguishes them.
    """
    result = _call(path=str(DATA))

    assert result["counts"]["DATE"] > 1


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


def test_unsupported_entity_type_reports_tool_error() -> None:
    """A bad entity_types value surfaces as a tool error, not a crash."""
    with pytest.raises(ToolError, match="unsupported entity types"):
        _call(path=str(DATA), entity_types=["PERSON"])
