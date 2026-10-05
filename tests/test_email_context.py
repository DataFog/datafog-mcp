"""Source email boundaries through actual MCP scan and file-copy tools."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.server import mcp


def call(tool: str, **arguments: Any) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, arguments)
            assert not result.is_error
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


@pytest.mark.parametrize("tool", ["datafog_redact", "datafog_mask", "datafog_remove"])
@pytest.mark.parametrize(
    ("filename", "source", "address"),
    [
        (".env", "SUPPORT_EMAIL=support@example.com", "support@example.com"),
        (".env.production", "export EMAIL='support@example.com'\n", "support@example.com"),
        ("config.env", 'EMAIL="o\'connor=tag@example.com"\n', "o'connor=tag@example.com"),
        ("contacts.sql", "'li.wei@example.com'", "li.wei@example.com"),
        (
            "dump.SQL",
            "-- 👋 contact\nINSERT INTO contacts (email) VALUES ('li.wei@example.com');\n",
            "li.wei@example.com",
        ),
        (
            "escaped.sql",
            "INSERT INTO contacts VALUES ('o''connor=tag@example.com');\n",
            "o''connor=tag@example.com",
        ),
    ],
)
def test_file_tools_preserve_assignment_and_quote_syntax(
    tmp_path: Path, tool: str, filename: str, source: str, address: str
) -> None:
    path = tmp_path / filename
    original = source.encode()
    path.write_bytes(original)
    scanned = call("datafog_scan", path=str(path), entity_types=["EMAIL"])
    assert scanned["counts"] == {"EMAIL": 1}
    finding = scanned["findings"][0]
    start = source.index(address)
    assert (finding["start"], finding["end"]) == (start, start + len(address))
    assert source[finding["start"] : finding["end"]] == address
    assert address not in json.dumps(scanned)
    result = call(tool, path=str(path), entity_types=["EMAIL"])
    replacement = (
        "[EMAIL]"
        if tool == "datafog_redact"
        else "*" * len(address)
        if tool == "datafog_mask"
        else ""
    )
    expected = source[:start] + replacement + source[start + len(address) :]
    output = Path(result["output_path"])
    assert output != path
    transformed = output.read_bytes().decode()
    assert transformed == expected
    assert address not in transformed
    assert result["counts"] == scanned["counts"]
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    ("input_format", "source", "expected"),
    [
        ("env", "EMAIL=customer=tag@example.com", "EMAIL=[EMAIL]"),
        ("sql", "SELECT 'o''connor@example.com';", "SELECT '[EMAIL]';"),
        ("text", "EMAIL=customer=tag@example.com", "[EMAIL]"),
    ],
)
def test_explicit_formats_override_filename(
    tmp_path: Path, input_format: str, source: str, expected: str
) -> None:
    path = tmp_path / ("export.env" if input_format == "text" else "export.txt")
    path.write_text(source)
    result = call(
        "datafog_redact", path=str(path), input_format=input_format, entity_types=["EMAIL"]
    )
    assert Path(result["output_path"]).read_text() == expected
    assert path.read_text() == source


def test_plain_text_and_csv_cells_keep_legitimate_local_parts(tmp_path: Path) -> None:
    address = "customer=tag@example.com"
    text = tmp_path / "address.txt"
    csv = tmp_path / "address.csv"
    text.write_text(address)
    csv.write_text(f"email\n{address}\n")
    for path in [text, csv]:
        scanned = call("datafog_scan", path=str(path), entity_types=["EMAIL"])
        finding = scanned["findings"][0]
        original = path.read_text()
        assert original[finding["start"] : finding["end"]] == address
        result = call("datafog_redact", path=str(path), entity_types=["EMAIL"])
        output = Path(result["output_path"]).read_text()
        assert address not in output and "customer=" not in output
        assert path.read_text() == original
    checked = call("datafog_check_text", text=address, entity_types=["EMAIL"])
    assert (checked["findings"][0]["start"], checked["findings"][0]["end"]) == (0, len(address))


def test_format_change_invalidates_scan_continuation(tmp_path: Path) -> None:
    path = tmp_path / "config.env"
    path.write_text("EMAIL=one@example.com\nOTHER=two@example.com\n")
    first = call("datafog_scan", path=str(path), limit=1, entity_types=["EMAIL"])
    with pytest.raises(ToolError, match="configuration changed"):
        call(
            "datafog_scan",
            path=str(path),
            input_format="text",
            offset=first["next_offset"],
            content_digest=first["content_digest"],
            entity_types=["EMAIL"],
        )
