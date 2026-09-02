"""End-to-end tests for the redaction tools."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.server import mcp

SOURCE = Path(__file__).parent / "data" / "garmin_export.csv"

EMAIL = "jack.smith@example.com"
PHONE = "415-555-0182"
POSTAL = "94117"


def _call(tool: str, **arguments: Any) -> dict[str, Any]:
    """
    Invoke a tool through an in-memory MCP client.

    Parameters:
      tool: The tool name to call.
      arguments: Tool arguments.
    Returns:
      The tool's structured result.
    """

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, arguments)
            return result.structured_content or {}

    return asyncio.run(run())


@pytest.fixture
def export(tmp_path: Path) -> Path:
    """
    A copy of the Garmin fixture inside the test's own directory.

    Redaction writes beside its input, so the checked-in fixture must
    not be the input.

    Returns:
      The path of the copy.
    """
    destination = tmp_path / "garmin_export.csv"
    destination.write_text(SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
    return destination


def test_redact_writes_a_masked_sibling(export: Path) -> None:
    """The copy lands beside the input with the identifiers masked."""
    result = _call("datafog_redact", path=str(export))

    written = Path(result["output_path"])
    text = written.read_text(encoding="utf-8")

    assert written == export.with_name("garmin_export_redacted.csv")
    assert EMAIL not in text
    assert PHONE not in text
    assert "*" * len(PHONE) in text


def test_redact_leaves_the_input_alone(export: Path) -> None:
    """The original still contains what it always did."""
    before = export.read_text(encoding="utf-8")

    _call("datafog_redact", path=str(export))

    assert export.read_text(encoding="utf-8") == before


def test_anonymize_writes_placeholders(export: Path) -> None:
    """Tokens preserve the type where masking would not."""
    result = _call("datafog_anonymize", path=str(export))

    written = Path(result["output_path"])
    text = written.read_text(encoding="utf-8")

    assert written == export.with_name("garmin_export_anonymized.csv")
    assert EMAIL not in text
    assert "[EMAIL_1]" in text


def test_response_carries_no_matched_value(export: Path) -> None:
    """
    The tally says what was replaced, never what it was.

    Returning the values would put in context exactly what the
    redaction just took out of the file.
    """
    payload = json.dumps(_call("datafog_redact", path=str(export)))

    for value in (EMAIL, PHONE, POSTAL):
        assert value not in payload

    assert "mapping" not in payload


def test_response_counts_by_type(export: Path) -> None:
    """Counts are reported per entity type."""
    result = _call("datafog_redact", path=str(export))

    assert result["counts"]["EMAIL"] >= 1
    assert result["entity_count"] == sum(result["counts"].values())
    assert result["strategy"] == "mask"


def test_explicit_output_path_is_honored(export: Path, tmp_path: Path) -> None:
    """A caller may name the destination."""
    destination = tmp_path / "clean.csv"

    result = _call("datafog_redact", path=str(export), output_path=str(destination))

    assert Path(result["output_path"]) == destination
    assert destination.exists()


def test_existing_output_is_not_overwritten(export: Path, tmp_path: Path) -> None:
    """A redaction never clobbers a file that is already there."""
    destination = tmp_path / "taken.csv"
    destination.write_text("keep me", encoding="utf-8")

    with pytest.raises(ToolError):
        _call("datafog_redact", path=str(export), output_path=str(destination))

    assert destination.read_text(encoding="utf-8") == "keep me"


def test_input_outside_the_roots_is_refused() -> None:
    """The policy applies to the tools, not just to reader."""
    with pytest.raises(ToolError):
        _call("datafog_redact", path="/etc/hosts")
