"""MCP selections reach native Core before detection, without changing copies."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from datafog_core import Finding, scan
from fastmcp import Client

from datafog_mcp import server
from datafog_mcp.config import DEFAULT_ENTITIES

if TYPE_CHECKING:
    from datafog_core import _ScanConfig

TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]
EMAIL = "person@example.com"
PHONE = "415-555-0182"


def call(tool: str, path: Path, **options: Any) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            result = await client.call_tool(tool, {"path": str(path), **options})
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("selection", [None, ["PHONE"]])
@pytest.mark.parametrize(
    "filename,body,core_format",
    [
        ("data.txt", f"Email: {EMAIL}\nPhone: {PHONE}\n", "text"),
        ("data.env", f"EMAIL={EMAIL}\nPHONE={PHONE}\n", "env"),
        ("data.sql", f"SELECT '{EMAIL}', '{PHONE}';\n", "sql"),
        ("data.csv", f"email,phone\n{EMAIL},{PHONE}\n", "text"),
        ("data.tsv", f"email\tphone\n{EMAIL}\t{PHONE}\n", "text"),
    ],
)
def test_selected_detectors_reach_core_for_every_file_tool(
    tool: str,
    selection: list[str] | None,
    filename: str,
    body: str,
    core_format: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = list(DEFAULT_ENTITIES) if selection is None else selection
    calls: list[_ScanConfig] = []

    def checked_scan(text: str, config: _ScanConfig | None = None) -> list[Finding]:
        assert config is not None
        assert "entities" in config
        assert "format" in config
        assert config["entities"] == expected
        assert config["format"] == core_format
        calls.append(config)
        found = scan(text, config)
        # Check the native result itself, before MCP's defensive result filter.
        assert {finding.entity_type for finding in found} <= set(expected)
        return found

    monkeypatch.setattr(server, "scan", checked_scan)
    source = tmp_path / filename
    source.write_bytes(body.encode())
    result = call(tool, source, entity_types=selection)
    assert calls
    selected_type = "EMAIL" if selection is None else "PHONE"
    assert result["counts"] == {selected_type: 1}
    assert result["entity_count"] == 1
    assert EMAIL not in json.dumps(result)
    assert PHONE not in json.dumps(result)
    assert source.read_bytes() == body.encode()
    if tool != "datafog_scan":
        copied = Path(result["output_path"]).read_text()
        selected_value = EMAIL if selection is None else PHONE
        untouched_value = PHONE if selection is None else EMAIL
        assert selected_value not in copied
        assert untouched_value in copied


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("extension,delimiter", [("csv", ","), ("tsv", "\t")])
def test_selected_labeled_detector_retains_header_context(
    tool: str, extension: str, delimiter: str, tmp_path: Path
) -> None:
    body = f"NPI{delimiter}email\r\n1234567893{delimiter}{EMAIL}\r\n"
    source = tmp_path / f"table.{extension}"
    source.write_bytes(body.encode())
    result = call(tool, source, entity_types=["NPI"])
    assert result["counts"] == {"NPI": 1}
    if tool == "datafog_scan":
        assert result["findings"] == [
            {
                "type": "NPI",
                "start": body.index("1234567893"),
                "end": body.index("1234567893") + 10,
                "record": 1,
                "column": 1,
            }
        ]
    else:
        copied = Path(result["output_path"]).read_bytes().decode()
        assert copied.startswith(f"NPI{delimiter}email\r\n")
        assert EMAIL in copied
        assert "1234567893" not in copied


@pytest.mark.parametrize("tool", TOOLS)
def test_duplicate_requested_types_keep_existing_behavior(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "data.txt"
    source.write_text(EMAIL)
    seen: list[list[str]] = []

    def checked_scan(text: str, config: _ScanConfig | None = None) -> list[Finding]:
        assert config is not None
        assert "entities" in config
        assert "format" in config
        assert config["entities"] == ["EMAIL"]
        seen.append(list(config["entities"]))
        return scan(text, config)

    monkeypatch.setattr(server, "scan", checked_scan)
    result = call(tool, source, entity_types=["EMAIL", "EMAIL"])
    assert seen == [["EMAIL"]]
    assert result["counts"] == {"EMAIL": 1}


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("extension", ["csv", "tsv"])
def test_table_suffix_overrides_env_prefix(tool: str, extension: str, tmp_path: Path) -> None:
    address = "customer=tag@example.com"
    body = f"email\n{address}\n"
    source = tmp_path / f".env.{extension}"
    source.write_text(body)
    result = call(tool, source, entity_types=["EMAIL"])
    assert result["counts"] == {"EMAIL": 1}
    if tool == "datafog_scan":
        assert result["findings"][0]["start"] == body.index(address)
        assert result["findings"][0]["end"] == body.index(address) + len(address)
    else:
        copied = Path(result["output_path"]).read_text()
        assert "customer=" not in copied
        assert address not in copied
