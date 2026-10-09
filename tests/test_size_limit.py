"""Verify exact byte limits across every file tool and input path."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.config import DEFAULT_MAX_BYTES
from datafog_mcp.server import mcp


def _call(tool: str, path: Path, **arguments: Any) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool("datafog_" + tool, {"path": str(path), **arguments})
            return result.structured_content or {}

    return asyncio.run(run())


def _sized_file(tmp_path: Path, size: int, input_format: str) -> Path:
    if input_format == "text":
        header = ""
        tail = "\nuser@example.com\n"
        suffix = ".log"
    else:
        delimiter = "," if input_format == "csv" else "\t"
        header = "padding" + delimiter + "email\r\n"
        tail = delimiter + "\r\n" + delimiter + "user@example.com\r\n"
        suffix = "." + input_format
    # Multibyte padding distinguishes a byte limit from a character limit.
    prefix = header + "🙂"
    padding = size - len((prefix + tail).encode("utf-8"))
    path = tmp_path / ("large" + suffix)
    path.write_bytes((prefix + "x" * padding + tail).encode("utf-8"))
    assert path.stat().st_size == size
    return path


@pytest.mark.parametrize("input_format", ["text", "csv", "tsv"])
@pytest.mark.parametrize("tool", ["scan", "redact", "mask", "remove"])
def test_file_at_byte_limit_is_processed_completely(
    tmp_path: Path, input_format: str, tool: str
) -> None:
    source = _sized_file(tmp_path, 10_000_000, input_format)
    original = source.read_bytes()
    result = _call(tool, source)
    assert result["entity_count"] == 1
    assert result["counts"] == {"EMAIL": 1}
    if tool == "scan":
        assert result["findings_listed"] is True
        finding = result["findings"][0]
        assert original.decode()[finding["start"] : finding["end"]] == "user@example.com"
        if input_format != "text":
            assert (finding["record"], finding["column"]) == (2, 2)
    else:
        output = Path(result["output_path"]).read_bytes()
        assert b"user@example.com" not in output
        assert output.startswith(original[:100])
        if tool == "redact":
            assert b"[EMAIL]" in output
        if input_format != "text":
            assert output.count(b"\r\n") == 3
    assert source.read_bytes() == original


@pytest.mark.parametrize("input_format", ["text", "csv", "tsv"])
@pytest.mark.parametrize("tool", ["scan", "redact", "mask", "remove"])
def test_file_one_byte_over_limit_is_refused_without_copy(
    tmp_path: Path, input_format: str, tool: str
) -> None:
    source = _sized_file(tmp_path, 10_000_001, input_format)
    original = source.read_bytes()
    output = tmp_path / "must-not-exist.txt"
    arguments = {} if tool == "scan" else {"output_path": str(output)}
    with pytest.raises(ToolError, match="limit"):
        _call(tool, source, **arguments)
    assert not output.exists()
    assert list(tmp_path.iterdir()) == [source]
    assert source.read_bytes() == original


def test_limit_is_ten_decimal_megabytes() -> None:
    assert DEFAULT_MAX_BYTES == 10_000_000
