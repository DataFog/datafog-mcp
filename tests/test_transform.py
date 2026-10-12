"""End-to-end tests for the transformation tools."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import paths
from datafog_mcp.paths import ALLOWED_ROOTS_VAR
from datafog_mcp.server import mcp

SOURCE = Path(__file__).parent / "data" / "garmin_export.csv"

EMAIL = "jack.smith@example.com"
PHONE = "415-555-0182"
POSTAL = "94117"
DATE = "1995-08-12"
TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]


@pytest.fixture
def identifiers(tmp_path: Path) -> Path:
    """A file with distinct email, phone, date, and ZIP matches."""
    source = tmp_path / "identifiers.txt"
    source.write_text(f"Email: {EMAIL}\nPhone: {PHONE}\nDOB: {DATE}\nZIP: {POSTAL}\n")
    return source


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


@pytest.mark.parametrize("tool", TOOLS)
def test_noisy_types_are_not_selected_by_default(identifiers: Path, tool: str) -> None:
    """Defaults detect/transform the email while preserving opt-in values."""
    before = identifiers.read_text()
    result = _call(tool, path=str(identifiers))

    assert result["counts"] == {"EMAIL": 1}
    assert result["entity_count"] == 1
    assert identifiers.read_text() == before
    if tool != "datafog_scan":
        written = Path(result["output_path"]).read_text()
        assert EMAIL not in written
        for value in (PHONE, DATE, POSTAL):
            assert value in written


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    ("entity", "value"), [("PHONE", PHONE), ("DATE", DATE), ("ZIP_CODE", POSTAL)]
)
def test_opt_in_selection_replaces_defaults(
    identifiers: Path, tool: str, entity: str, value: str
) -> None:
    """Explicit opt-in works for every tool and leaves unselected values alone."""
    before = identifiers.read_text()
    result = _call(tool, path=str(identifiers), entity_types=[entity])

    assert result["counts"] == {entity: 1}
    assert result["entity_count"] == 1
    assert identifiers.read_text() == before
    if tool != "datafog_scan":
        written = Path(result["output_path"]).read_text()
        assert value not in written
        for unselected in {EMAIL, PHONE, DATE, POSTAL} - {value}:
            assert unselected in written


@pytest.fixture
def export(tmp_path: Path) -> Path:
    """
    A copy of the Garmin fixture inside the test's own directory.

    The tools write beside their input, so the checked-in fixture must
    not be the input.

    Returns:
      The path of the copy.
    """
    destination = tmp_path / "garmin_export.csv"
    destination.write_text(SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
    return destination


def test_redact_writes_labelled_placeholders(export: Path) -> None:
    """The copy names the kind of thing it removed."""
    result = _call("datafog_redact", path=str(export))

    written = Path(result["output_path"])
    text = written.read_text(encoding="utf-8")

    assert written == export.with_name("garmin_export_redacted.csv")
    assert EMAIL not in text
    assert "[EMAIL]" in text
    assert PHONE in text
    assert result["strategy"] == "redact"


def test_mask_preserves_length(export: Path) -> None:
    """Masking covers each value character for character."""
    result = _call("datafog_mask", path=str(export))

    written = Path(result["output_path"])
    text = written.read_text(encoding="utf-8")

    assert written == export.with_name("garmin_export_masked.csv")
    assert EMAIL not in text
    assert "*" * len(EMAIL) in text
    assert PHONE in text
    assert result["strategy"] == "mask"


def test_remove_leaves_no_trace(export: Path) -> None:
    """Removal deletes the span without marking where it was."""
    result = _call("datafog_remove", path=str(export))

    written = Path(result["output_path"])
    text = written.read_text(encoding="utf-8")

    assert written == export.with_name("garmin_export_removed.csv")
    assert EMAIL not in text
    assert "[EMAIL]" not in text
    assert "*" not in text
    assert result["strategy"] == "remove"


def test_the_input_is_left_alone(export: Path) -> None:
    """The original still contains what it always did."""
    before = export.read_text(encoding="utf-8")

    _call("datafog_redact", path=str(export))

    assert export.read_text(encoding="utf-8") == before


def test_response_carries_no_matched_value(export: Path) -> None:
    """
    The tally says what was replaced, never what it was.

    Returning the values would put in context exactly what the
    transformation just took out of the file.
    """
    payload = json.dumps(_call("datafog_redact", path=str(export)))

    for value in (EMAIL, PHONE, POSTAL):
        assert value not in payload


def test_response_counts_by_type(export: Path) -> None:
    """Counts are reported per entity type."""
    result = _call("datafog_mask", path=str(export))

    assert result["counts"]["EMAIL"] == 1
    assert result["entity_count"] == sum(result["counts"].values())


def test_entity_types_narrows_what_is_replaced(export: Path) -> None:
    """
    Only the requested types are transformed.

    core detects every supported label and offers no way to narrow it,
    so this exercises the filtering datafog-mcp does on the findings.
    """
    result = _call("datafog_redact", path=str(export), entity_types=["EMAIL"])

    text = Path(result["output_path"]).read_text(encoding="utf-8")

    assert "[EMAIL]" in text
    assert PHONE in text
    assert result["counts"] == {"EMAIL": 1}


def test_explicit_output_path_is_honored(export: Path, tmp_path: Path) -> None:
    """A caller may name the destination."""
    destination = tmp_path / "clean.csv"

    result = _call("datafog_redact", path=str(export), output_path=str(destination))

    assert Path(result["output_path"]) == destination
    assert destination.exists()


def test_existing_output_is_not_overwritten(export: Path, tmp_path: Path) -> None:
    """A transformation never clobbers a file already there."""
    destination = tmp_path / "taken.csv"
    destination.write_text("keep me", encoding="utf-8")

    with pytest.raises(ToolError):
        _call(
            "datafog_redact",
            path=str(export),
            output_path=str(destination),
        )

    assert destination.read_text(encoding="utf-8") == "keep me"


def test_input_outside_the_roots_is_refused() -> None:
    """The policy applies to the tools, not just to reader."""
    with pytest.raises(ToolError):
        _call("datafog_redact", path="/etc/hosts")


def test_tools_cannot_widen_their_own_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The maintainer's escalation: write "/" into the roots file through
    a transform, then have the next call read it as the policy.

    Both layers must hold, and the policy must be unchanged afterward.
    """
    config = tmp_path / ".config" / "datafog"
    config.mkdir(parents=True)
    roots_file = config / "allowed_roots"
    monkeypatch.setattr(paths, "ROOTS_FILE", roots_file)
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, str(tmp_path))

    payload = tmp_path / "payload.txt"
    payload.write_text("/\n", encoding="utf-8")

    with pytest.raises(ToolError):
        _call(
            "datafog_redact",
            path=str(payload),
            output_path=str(roots_file),
        )

    assert not roots_file.exists()
    assert paths.allowed_roots() == (tmp_path.resolve(),)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
@pytest.mark.parametrize("tool", ["datafog_redact", "datafog_mask", "datafog_remove"])
@pytest.mark.usefixtures("umask_022")
def test_private_input_yields_private_copy(export: Path, tool: str) -> None:
    """
    A file only its owner can read produces a copy only its owner can read.

    Under the common umask of 022, a copy created with default permissions
    would be readable by every user on the machine.

    Parameters:
      export: The input file.
      tool: The transformation under test.
    """
    export.chmod(0o600)

    result = _call(tool, path=str(export))

    assert stat.S_IMODE(Path(result["output_path"]).stat().st_mode) == 0o600


def test_utf8_bom_survives_into_the_copy(tmp_path: Path) -> None:
    """
    A copy keeps the input's byte-order mark.

    Excel reads a BOM-less CSV as the wrong encoding, so dropping it would
    corrupt accented names when the copy is opened.

    Parameters:
      tmp_path: Holds the input and the copy.
    """
    source = tmp_path / "excel.csv"
    source.write_bytes(b"\xef\xbb\xbfname,email\nJack,jack.smith@example.com\n")

    result = _call("datafog_redact", path=str(source))

    assert Path(result["output_path"]).read_bytes().startswith(b"\xef\xbb\xbfname")


@pytest.mark.parametrize("tool", ["datafog_redact", "datafog_mask", "datafog_remove"])
def test_scan_counts_what_the_write_tools_replace(tmp_path: Path, tool: str) -> None:
    """
    A scan reports exactly the spans a write tool would replace.

    The fixture's own entities plus two overlapping values, an NPI that is also
    a phone number and a credential URI containing an email address.

    Parameters:
      tmp_path: Directory for the input and copy.
      tool: The write tool compared against the scan.
    """
    source = tmp_path / "mixed.txt"
    source.write_text(
        SOURCE.read_text(encoding="utf-8")
        + "Provider NPI: 1234567893\n"
        + "DATABASE_URL=postgres://admin:hunter2@db.example.com:5432/prod\n",
        encoding="utf-8",
    )

    scanned = _call("datafog_scan", path=str(source))
    written = _call(tool, path=str(source))

    assert scanned["counts"] == written["counts"]
    assert scanned["entity_count"] == written["entity_count"]
