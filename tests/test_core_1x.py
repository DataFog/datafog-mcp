"""
Behaviour that moving to datafog-core 1.x must keep, and the one it changes.

Core 1.x turns more detectors on in its own default scan and refuses to
transform detections that partly overlap. The server's defaults are a product
decision and stay explicit; a refused overlap fails the whole request with a
message that names entity types only.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from datafog_core import DataFogFindingError
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import server
from datafog_mcp.config import DEFAULT_ENTITIES, SUPPORTED_ENTITIES
from datafog_mcp.server import mcp

ALL_TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]
WRITE_TOOLS = ["datafog_redact", "datafog_mask", "datafog_remove"]

# Synthetic values: a card-network test number and a reserved example domain.
CARD = "4111 1111 1111 1111"
URI = "postgres://app:s3cretpw@db.example.com:5432/app"
# A semicolon does not end a connection string, so its match runs on into the
# card's first group: the two detections overlap and neither contains the
# other.
OVERLAPPING = f"{URI};{CARD}"
ACCOUNT = "000123456789"
STREET = "45 Sample Avenue"
LABELED = f"Account number: {ACCOUNT}\nStreet address: {STREET}\n"


def call(tool: str, path: Path, **arguments: Any) -> dict[str, Any]:
    """Invoke the real server through an in-memory MCP client."""

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, {"path": str(path), **arguments})
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


def test_default_types_are_unchanged_by_core_defaults() -> None:
    """The ten default types do not follow core's wider default scan."""
    assert DEFAULT_ENTITIES == (
        "API_KEY",
        "BEARER_TOKEN",
        "CREDENTIAL_URI",
        "CREDIT_CARD",
        "EMAIL",
        "JWT",
        "NPI",
        "PRIVATE_KEY",
        "SSN",
        "US_ROUTING_NUMBER",
    )


def test_opt_in_types_are_exactly_the_documented_ones() -> None:
    """A core release that adds or drops a selectable type must be noticed."""
    assert SUPPORTED_ENTITIES - set(DEFAULT_ENTITIES) == {
        "ACCOUNT_NUMBER",
        "DATE",
        "IP_ADDRESS",
        "PHONE",
        "STREET_ADDRESS",
        "ZIP_CODE",
    }


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_new_core_types_stay_off_by_default(tool: str, tmp_path: Path) -> None:
    """Labeled account numbers and street addresses need an explicit selection."""
    source = tmp_path / "labeled.txt"
    source.write_text(LABELED, encoding="utf-8")

    result = call(tool, source)

    assert result["entity_count"] == 0
    assert result["counts"] == {}
    if tool != "datafog_scan":
        assert Path(result["output_path"]).read_text(encoding="utf-8") == LABELED


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_new_core_types_are_available_on_request(tool: str, tmp_path: Path) -> None:
    """Selecting the two labeled types finds and transforms their values."""
    source = tmp_path / "labeled.txt"
    source.write_text(LABELED, encoding="utf-8")

    result = call(tool, source, entity_types=["ACCOUNT_NUMBER", "STREET_ADDRESS"])

    assert result["counts"] == {"ACCOUNT_NUMBER": 1, "STREET_ADDRESS": 1}
    assert ACCOUNT not in json.dumps(result)
    assert STREET not in json.dumps(result)
    if tool == "datafog_scan":
        spans = {(item["type"], item["start"], item["end"]) for item in result["findings"]}
        assert spans == {
            ("ACCOUNT_NUMBER", LABELED.index(ACCOUNT), LABELED.index(ACCOUNT) + len(ACCOUNT)),
            ("STREET_ADDRESS", LABELED.index(STREET), LABELED.index(STREET) + len(STREET)),
        }
    else:
        copied = Path(result["output_path"]).read_text(encoding="utf-8")
        assert ACCOUNT not in copied
        assert STREET not in copied
        assert copied.startswith("Account number: ")
    assert source.read_text(encoding="utf-8") == LABELED


@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize(
    ("filename", "body"),
    [
        ("mixed.txt", f"note {OVERLAPPING} end\n"),
        ("mixed.csv", f"note\n{OVERLAPPING}\n"),
    ],
)
def test_partly_overlapping_detections_fail_closed(
    tool: str, filename: str, body: str, tmp_path: Path
) -> None:
    """
    A partial overlap is refused, not resolved by leaving part of a value.

    Replacing only the connection string would leave most of the card number
    in the copy, and replacing only the card would leave the connection string.
    """
    source = tmp_path / filename
    source.write_text(body, encoding="utf-8")

    with pytest.raises(ToolError) as refused:
        call(tool, source)

    message = str(refused.value)
    assert "partly overlap (CREDENTIAL_URI, CREDIT_CARD)" in message
    assert "entity_types" in message
    assert CARD not in message
    assert URI not in message
    assert "1111" not in message
    assert "s3cretpw" not in message
    assert "example" not in message
    assert sorted(path.name for path in tmp_path.iterdir()) == [filename]
    assert source.read_text(encoding="utf-8") == body


@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize("entity", ["CREDIT_CARD", "CREDENTIAL_URI"])
def test_narrower_selection_resolves_an_overlap(tool: str, entity: str, tmp_path: Path) -> None:
    """Following the error's advice produces a result for the selected type."""
    source = tmp_path / "mixed.txt"
    source.write_text(OVERLAPPING, encoding="utf-8")

    result = call(tool, source, entity_types=[entity])

    assert result["counts"] == {entity: 1}
    assert CARD not in json.dumps(result)
    assert URI not in json.dumps(result)


@pytest.mark.parametrize("tool", WRITE_TOOLS)
def test_contained_detections_still_resolve(tool: str, tmp_path: Path) -> None:
    """
    One detection wholly inside another is resolved, as before.

    The address-shaped credentials of a connection string sit inside the
    CREDENTIAL_URI match, so the whole string is replaced once.
    """
    source = tmp_path / "service.txt"
    source.write_text(f"url {URI} end\n", encoding="utf-8")

    result = call(tool, source)

    assert result["counts"] == {"CREDENTIAL_URI": 1}
    copied = Path(result["output_path"]).read_text(encoding="utf-8")
    assert "s3cretpw" not in copied
    assert "db.example.com" not in copied


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_overlap_refusal_without_an_index_names_no_types(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A conflict the engine cannot locate is still refused, with no detail."""

    def conflict(*_args: Any, **_kwargs: Any) -> Any:
        error = DataFogFindingError(f"conflict near {URI}")
        error.code = "review_conflict"
        raise error

    monkeypatch.setattr(server, "transform", conflict)
    source = tmp_path / "mixed.txt"
    source.write_text(OVERLAPPING, encoding="utf-8")

    with pytest.raises(ToolError) as refused:
        call(tool, source)

    assert "partly overlap, so" in str(refused.value)
    assert URI not in str(refused.value)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["mixed.txt"]


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_other_finding_errors_keep_their_details_withheld(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the overlap refusal is shown; any other engine error stays masked."""

    def invalid(*_args: Any, **_kwargs: Any) -> Any:
        raise DataFogFindingError(f"finding text was {URI}")

    monkeypatch.setattr(server, "transform", invalid)
    source = tmp_path / "mixed.txt"
    source.write_text(URI, encoding="utf-8")

    with pytest.raises(ToolError) as refused:
        call(tool, source)

    assert "DataFogFindingError" in str(refused.value)
    assert "details are withheld" in str(refused.value)
    assert URI not in str(refused.value)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["mixed.txt"]
