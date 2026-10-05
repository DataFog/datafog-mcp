"""Actual MCP calls preserve table structure and expose only source locations."""

from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.server import mcp

EMAIL = "person@example.com"
HEADER = "sensitive-header@example.com"
TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]


def call(tool: str, source: Path, **options: Any) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(
                tool, {"path": str(source), "entity_types": ["EMAIL"], **options}
            )
            assert EMAIL not in str(result.content)
            assert HEADER not in str(result.content)
            return result.structured_content or {}

    return asyncio.run(run())


def rows(text: str, delimiter: str) -> list[list[str]]:
    return list(
        csv.reader(io.StringIO(text.removeprefix("\ufeff"), newline=""), delimiter=delimiter)
    )


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("extension,delimiter", [(".CSV", ","), (".TSV", "\t")])
def test_tables_keep_shape_unmatched_syntax_and_original_offsets(
    tool: str, extension: str, delimiter: str, tmp_path: Path
) -> None:
    text = (
        f"\ufeffname{delimiter}{HEADER}{delimiter}notes{delimiter}notes\r\n"
        f'José😀{delimiter}"said ""hello"": {EMAIL}"{delimiter}'
        f'"comma, tab\t and\r\nline"{delimiter}\r\n'
        f"李{delimiter}{EMAIL}{delimiter}same{delimiter}tail"
    )
    source = tmp_path / f"input{extension}"
    source.write_bytes(text.encode())
    result = call(tool, source)
    assert result["entity_count"] == 2
    assert result["counts"] == {"EMAIL": 2}
    assert HEADER not in json.dumps(result)
    assert source.read_bytes() == text.encode()
    if tool == "datafog_scan":
        assert result["findings"] == [
            {
                "type": "EMAIL",
                "start": text.index(EMAIL),
                "end": text.index(EMAIL) + len(EMAIL),
                "record": 1,
                "column": 2,
            },
            {
                "type": "EMAIL",
                "start": text.rindex(EMAIL),
                "end": text.rindex(EMAIL) + len(EMAIL),
                "record": 2,
                "column": 2,
            },
        ]
    else:
        output = Path(result["output_path"]).read_bytes().decode()
        before = rows(text, delimiter)
        expected = rows(text, delimiter)
        replacement = {
            "datafog_redact": "[EMAIL]",
            "datafog_mask": "*" * len(EMAIL),
            "datafog_remove": "",
        }[tool]
        for record in expected[1:]:
            record[1] = record[1].replace(EMAIL, replacement)
        assert rows(output, delimiter) == expected
        assert output.startswith("\ufeff")
        assert "\r\n" in output and not output.endswith("\n")
        assert '"comma, tab\t and\r\nline"' in output
        assert before[0] == rows(output, delimiter)[0]


@pytest.mark.parametrize("tool", TOOLS)
def test_headerless_tables_process_first_record(tool: str, tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    source.write_text(f"{EMAIL}\n", encoding="utf-8")
    result = call(tool, source, has_header=False)
    assert result["entity_count"] == 1
    if tool == "datafog_scan":
        assert result["findings"][0]["record"] == 1
    elif tool == "datafog_remove":
        assert Path(result["output_path"]).read_bytes() == b'""\n'


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize(
    "malformed",
    [
        f'email\n"{EMAIL}',
        f'email\n"{EMAIL}"junk\n',
        f"email\n{EMAIL},extra\n",
        f"email\n{EMAIL}\n\n",
        f'email\nun"quoted {EMAIL}\n',
    ],
)
def test_malformed_table_never_writes_a_copy_or_returns_partial_results(
    tool: str, malformed: str, tmp_path: Path
) -> None:
    source = tmp_path / "input.csv"
    source.write_text(malformed, encoding="utf-8")
    with pytest.raises(ToolError, match="Malformed CSV") as excinfo:
        call(tool, source)
    assert EMAIL not in str(excinfo.value)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["input.csv"]


@pytest.mark.parametrize("tool", TOOLS)
def test_explicit_format_and_text_override(tool: str, tmp_path: Path) -> None:
    source = tmp_path / "export.txt"
    source.write_text(f"email\tkeep\n{EMAIL}\tvalue\n", encoding="utf-8")
    result = call(tool, source, input_format="tsv")
    assert result["entity_count"] == 1
    if tool == "datafog_scan":
        assert result["findings"][0]["column"] == 1
        # Headerless/malformed exports can still be deliberately scanned as text.
        source = tmp_path / "bad.csv"
        source.write_text(f'"{EMAIL}', encoding="utf-8")
        text_result = call(tool, source, input_format="text")
        assert text_result["entity_count"] == 1
        assert "record" not in text_result["findings"][0]


@pytest.mark.parametrize("tool", TOOLS)
def test_no_findings_copy_is_byte_identical(tool: str, tmp_path: Path) -> None:
    text = b'\xef\xbb\xbf"header",other\r\n"comma, and ""quote""",\r\n'
    source = tmp_path / "input.csv"
    source.write_bytes(text)
    result = call(tool, source)
    assert result["entity_count"] == 0
    if tool != "datafog_scan":
        assert Path(result["output_path"]).read_bytes() == text


@pytest.mark.parametrize("tool", TOOLS)
def test_headers_supply_npi_and_routing_context(tool: str, tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    text = "NPI,routing number\n1234567893,021000021\n"
    source.write_text(text, encoding="utf-8")
    result = call(tool, source, entity_types=["NPI", "US_ROUTING_NUMBER"])
    assert result["counts"] == {"NPI": 1, "US_ROUTING_NUMBER": 1}
    assert result["entity_count"] == 2
    if tool == "datafog_scan":
        assert [(item["record"], item["column"]) for item in result["findings"]] == [(1, 1), (1, 2)]
    else:
        output = Path(result["output_path"]).read_text(encoding="utf-8")
        assert rows(output, ",")[0] == ["NPI", "routing number"]
        assert "1234567893" not in output
        assert "021000021" not in output
    assert source.read_text(encoding="utf-8") == text
