"""Email boundaries through actual MCP scan and file-copy tools."""

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
    """Invoke the real server through an in-memory MCP client."""

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, arguments)
            assert not result.is_error
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


@pytest.mark.parametrize("tool", ["datafog_redact", "datafog_mask", "datafog_remove"])
@pytest.mark.parametrize(
    ("filename", "input_format", "source", "address"),
    [
        (".env", "auto", "SUPPORT_EMAIL=support@example.com", "support@example.com"),
        (".env.production", "auto", "export EMAIL='support@example.com'\n", "support@example.com"),
        ("config.ENV", "auto", 'EMAIL="o\'connor=tag@example.com"\n', "o'connor=tag@example.com"),
        ("contacts.sql", "auto", "'li.wei@example.com'", "li.wei@example.com"),
        (
            "dump.SQL",
            "auto",
            "-- 👋 contact\nINSERT INTO contacts (email) VALUES ('li.wei@example.com');\n",
            "li.wei@example.com",
        ),
        (
            "escaped.sql",
            "auto",
            "INSERT INTO contacts VALUES ('o''connor=tag@example.com');\n",
            "o''connor=tag@example.com",
        ),
        ("export.txt", "env", "EMAIL=customer=tag@example.com", "customer=tag@example.com"),
        ("export.txt", "sql", "SELECT 'o''connor@example.com';", "o''connor@example.com"),
        # Core 1.4 trims label syntax from plain-text email spans: one leading
        # identifier= prefix is not part of the address, and an inner = stays.
        ("export.env", "text", "EMAIL=customer=tag@example.com", "customer=tag@example.com"),
        # An explicit text format overrides an ENV or SQL filename. The row
        # above gives the same span under text and env boundaries, so these
        # two carry the proof: env and sql boundaries would each report the
        # whole string here, and text boundaries report the address alone.
        ("export.env", "text", "my.key=tag@example.com", "tag@example.com"),
        ("x.sql", "text", "customer=tag@example.com", "tag@example.com"),
        ("address.txt", "auto", "customer=tag@example.com", "tag@example.com"),
        ("address.csv", "auto", "email\ncustomer=tag@example.com\n", "tag@example.com"),
    ],
)
def test_email_boundaries_preserve_surrounding_syntax(
    tmp_path: Path, tool: str, filename: str, input_format: str, source: str, address: str
) -> None:
    """Scan offsets and every write agree on the email's original source span."""
    path = tmp_path / filename
    original = source.encode()
    path.write_bytes(original)
    arguments: dict[str, Any] = {"path": str(path), "entity_types": ["EMAIL"]}
    if input_format != "auto":
        arguments["input_format"] = input_format
    scanned = call("datafog_scan", **arguments)
    assert scanned["counts"] == {"EMAIL": 1}
    finding = scanned["findings"][0]
    start = source.index(address)
    assert (finding["start"], finding["end"]) == (start, start + len(address))
    assert source[finding["start"] : finding["end"]] == address
    assert address not in json.dumps(scanned)

    result = call(tool, **arguments)
    replacement = (
        "[EMAIL]"
        if tool == "datafog_redact"
        else "*" * len(address)
        if tool == "datafog_mask"
        else ""
    )
    expected = source[:start] + replacement + source[start + len(address) :]
    if filename == "address.csv" and input_format == "auto":
        # Table processing preserves the email span and quotes the whole
        # changed cell, which since core 1.4 keeps its "customer=" label.
        assert (finding["record"], finding["column"]) == (1, 1)
        cell = source.index("\n") + 1
        expected = (
            source[:cell]
            + '"'
            + source[cell:start]
            + replacement
            + '"'
            + source[start + len(address) :]
        )
    output = Path(result["output_path"])
    assert output != path
    assert output.read_bytes().decode() == expected
    assert address not in json.dumps(result)
    assert result["counts"] == scanned["counts"]
    assert path.read_bytes() == original


def test_plain_text_keeps_a_single_quote_after_a_label_in_the_match(tmp_path: Path) -> None:
    """A label and an opening double quote are trimmed; a single quote is not."""
    path = tmp_path / "notes.txt"
    source = "email='li.wei@example.com'\nemail=\"li.wei@example.com\"\n"
    path.write_text(source, encoding="utf-8")
    scanned = call("datafog_scan", path=str(path), entity_types=["EMAIL"])
    single = source.index("'li.wei")
    double = source.index('"li.wei') + 1
    assert [(item["start"], item["end"]) for item in scanned["findings"]] == [
        (single, single + len("'li.wei@example.com")),
        (double, double + len("li.wei@example.com")),
    ]
    result = call("datafog_redact", path=str(path), entity_types=["EMAIL"])
    copy = Path(result["output_path"]).read_text(encoding="utf-8")
    assert copy == 'email=[EMAIL]\'\nemail="[EMAIL]"\n'


@pytest.mark.parametrize(
    "tool", ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]
)
def test_unsupported_format_is_refused(tool: str) -> None:
    """The schema refuses unknown formats before reading or writing a file."""
    with pytest.raises(ToolError, match="input_format"):
        call(tool, path="/does/not/exist.txt", input_format="unknown")
