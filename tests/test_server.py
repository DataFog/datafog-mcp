"""End-to-end tests for the datafog_scan tool."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.findings import MAX_LISTED_FINDINGS
from datafog_mcp.paths import ALLOWED_ROOTS_VAR
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
    result = _call(path=str(DATA), entity_types=["EMAIL", "PHONE", "ZIP_CODE"])

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


def test_reports_credentials_without_their_values(tmp_path: Path) -> None:
    """
    Credentials are detected, and neither value reaches the response.

    Guards against engine types being silently filtered. Before the
    supported set was read from the engine, a type core could report but
    this server did not list was dropped without a trace.

    The key is assembled at runtime so no scannable literal lands in the
    repository.
    """
    key = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
    env = tmp_path / "app.env"
    env.write_text(
        f"API_KEY={key}\nDATABASE_URL=postgres://admin:hunter2@db.example.com:5432/prod\n"
    )

    result = _call(path=str(env))
    payload = json.dumps(result)

    assert result["counts"]["API_KEY"] == 1
    assert result["counts"]["CREDENTIAL_URI"] == 1
    assert key not in payload
    assert "hunter2" not in payload


def test_date_over_matches_activity_dates() -> None:
    """
    Activity dates register as DATE alongside the real birth date.

    Documents a known precision gap: the file holds one date of birth
    and several activity dates, and nothing distinguishes them.
    """
    result = _call(path=str(DATA), entity_types=["DATE"])

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


def test_undeclared_mode_is_refused() -> None:
    """A mode the schema does not offer is refused before any work is done."""
    with pytest.raises(ToolError):
        _call(path=str(DATA), mode="summary")


def test_unsupported_entity_type_reports_tool_error() -> None:
    """
    A type the engine cannot report is refused at the schema.

    PERSON needs structured input the server never passes, so a text scan
    could only return nothing for it and report that as success.
    """
    with pytest.raises(ToolError, match="entity_types"):
        _call(path=str(DATA), entity_types=["PERSON"])


@pytest.mark.parametrize(
    ("setting", "reason"),
    [("", "lists no allowed roots"), ("Downloads", "not an absolute path")],
)
def test_policy_problems_reach_the_agent(
    setting: str, reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    An empty or malformed policy refuses with its reason, not a generic error.

    Parameters:
      setting: A value for the roots variable.
      reason: What the refusal should say.
      monkeypatch: Sets the roots variable.
    """
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, setting)

    with pytest.raises(ToolError, match=reason):
        _call(path=str(DATA))


def test_empty_entity_types_is_refused() -> None:
    """
    An empty selection is an error, not a request for the defaults.

    It used to select every default type, so a caller asking for "none of
    these" got all of them. Omit the argument to get the defaults.
    """
    with pytest.raises(ToolError, match="at least 1 item"):
        _call(path=str(DATA), entity_types=[])


def _scan_text(tmp_path: Path, text: str, **arguments: Any) -> dict[str, Any]:
    """
    Scan a file holding the given text.

    Parameters:
      tmp_path: Directory for the file.
      text: File contents.
      arguments: Extra tool arguments.
    Returns:
      The scan result.
    """
    source = tmp_path / "input.txt"
    source.write_text(text, encoding="utf-8")
    return _call(path=str(source), **arguments)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Provider NPI: 1234567893\n", {"NPI": 1}),
        ("DATABASE_URL=postgres://admin:hunter2@db.example.com:5432/prod\n", {"CREDENTIAL_URI": 1}),
    ],
    ids=["npi-is-not-also-a-phone", "credential-uri-is-not-also-an-email"],
)
def test_overlapping_findings_are_counted_once(
    tmp_path: Path, text: str, expected: dict[str, int]
) -> None:
    """
    One value matched by two detectors is reported once, as the write tools treat it.

    Parameters:
      tmp_path: Directory for the input.
      text: A value two detectors both match.
      expected: The single finding that should be reported.
    """
    result = _scan_text(tmp_path, text)

    assert result["counts"] == expected
    assert result["entity_count"] == 1


def test_narrowing_keeps_the_requested_type(tmp_path: Path) -> None:
    """
    Asking only for PHONE still finds a number that an NPI would otherwise win.

    Overlaps are resolved among the requested types, not before narrowing.

    Parameters:
      tmp_path: Directory for the input.
    """
    result = _scan_text(tmp_path, "Provider NPI: 1234567893\n", entity_types=["PHONE"])

    assert result["counts"] == {"PHONE": 1}


def test_dense_file_returns_counts_without_locations(tmp_path: Path) -> None:
    """
    A file with more findings than the limit still reports every one in its counts.

    Parameters:
      tmp_path: Directory for the input.
    """
    over = MAX_LISTED_FINDINGS + 1
    text = "".join(f"user{i}@example.com\n" for i in range(over))
    result = _scan_text(tmp_path, text)

    assert result["counts"] == {"EMAIL": over}
    assert result["findings"] == []
    assert result["findings_listed"] is False


def test_full_listing_fits_the_context_budget(tmp_path: Path) -> None:
    """
    The largest listed response stays under Claude Code's 25,000-token cap.

    The worst case is the longest type name with offsets late in the file, so
    the findings are PostgreSQL URIs after a megabyte of filler. Three
    characters per token overestimates.

    Parameters:
      tmp_path: Directory for the input.
    """
    filler = "x" * 999_000 + "\n"
    uris = "".join(f"postgres://app:pw{i}@db.example.com/x\n" for i in range(MAX_LISTED_FINDINGS))
    result = _scan_text(tmp_path, filler + uris)

    assert result["counts"] == {"CREDENTIAL_URI": MAX_LISTED_FINDINGS}
    assert result["findings_listed"] is True
    assert len(json.dumps(result)) // 3 < 25_000
