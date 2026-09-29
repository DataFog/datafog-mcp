"""
The no-values contract holds when tools fail, not only when they succeed.

Every tool promises that no response carries a matched value. An engine or
filesystem exception whose message holds file content would break that
promise through the error channel, reaching the client and the server's
stderr. These tests inject a sentinel into each failure point and check both.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.client import CallToolResult
from fastmcp.exceptions import ToolError

from datafog_mcp import server
from datafog_mcp.server import mcp

SENTINEL = "synthetic-sensitive-value@example.com"

ALL_TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]
WRITE_TOOLS = ["datafog_redact", "datafog_mask", "datafog_remove"]


def _call(tool: str, **arguments: Any) -> CallToolResult:
    """
    Invoke a tool through an in-memory MCP client.

    Parameters:
      tool: The tool name to call.
      arguments: Tool arguments.
    Returns:
      The full result, content blocks included.
    """

    async def run() -> CallToolResult:
        async with Client(mcp) as client:
            return await client.call_tool(tool, arguments)

    return asyncio.run(run())


def _raise_sentinel(*_args: Any, **_kwargs: Any) -> Any:
    """
    Stand in for an engine or I/O call that fails with content in its message.

    Parameters:
      _args: Ignored.
      _kwargs: Ignored.
    Returns:
      Never returns.
    """
    raise RuntimeError(f"engine choked on {SENTINEL}")


def _assert_contained(
    tool: str,
    source: Path,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Call a tool expected to fail and check the sentinel went nowhere.

    Parameters:
      tool: The tool name to call.
      source: The input file.
      capfd: Captures the process's stdout and stderr.
      caplog: Captures records reaching the logging system.
    """
    with pytest.raises(ToolError) as excinfo:
        _call(tool, path=str(source))

    captured = capfd.readouterr()
    assert SENTINEL not in str(excinfo.value)
    assert SENTINEL not in captured.out
    assert SENTINEL not in captured.err
    assert SENTINEL not in caplog.text


@pytest.fixture
def source(tmp_path: Path) -> Path:
    """
    A small input file in the test's own directory.

    Returns:
      The path of the file.
    """
    path = tmp_path / "contacts.csv"
    path.write_text("name,email\nJack,jack.smith@example.com\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_scan_failure_carries_no_content(
    tool: str,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    An exception from the detector reaches neither the client nor stderr.

    Parameters:
      tool: The tool under test.
      source: The input file.
      monkeypatch: Replaces the engine's scan.
      capfd: Captures stdout and stderr.
      caplog: Captures log records.
    """
    monkeypatch.setattr(server, "scan", _raise_sentinel)
    _assert_contained(tool, source, capfd, caplog)


@pytest.mark.parametrize("tool", WRITE_TOOLS)
def test_transform_failure_carries_no_content(
    tool: str,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    An exception from the transformer reaches neither the client nor stderr.

    Parameters:
      tool: The tool under test.
      source: The input file.
      monkeypatch: Replaces the engine's transform.
      capfd: Captures stdout and stderr.
      caplog: Captures log records.
    """
    monkeypatch.setattr(server, "transform", _raise_sentinel)
    _assert_contained(tool, source, capfd, caplog)


@pytest.mark.parametrize("tool", WRITE_TOOLS)
def test_write_failure_carries_no_content(
    tool: str,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    An unexpected I/O error while writing the copy stays contained.

    Parameters:
      tool: The tool under test.
      source: The input file.
      monkeypatch: Replaces the file writer.
      capfd: Captures stdout and stderr.
      caplog: Captures log records.
    """
    monkeypatch.setattr(server, "write_text_file", _raise_sentinel)
    _assert_contained(tool, source, capfd, caplog)


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_success_carries_no_values(tool: str, source: Path) -> None:
    """
    A successful call leaves the matched value out of every part of the result.

    Checks the content blocks as well as the structured result, since a client
    may render either.

    Parameters:
      tool: The tool under test.
      source: The input file.
    """
    result = _call(tool, path=str(source))

    blocks = " ".join(getattr(block, "text", "") for block in result.content)
    assert "jack.smith@example.com" not in blocks
    assert "jack.smith@example.com" not in str(result.structured_content)


def test_expected_errors_keep_their_message(tmp_path: Path) -> None:
    """
    Containment does not flatten the errors an agent can act on.

    A missing path should still say so, rather than collapsing into the same
    generic message as an internal failure.

    Parameters:
      tmp_path: Supplies a directory with no such file in it.
    """
    with pytest.raises(ToolError, match="no such file"):
        _call("datafog_scan", path=str(tmp_path / "absent.csv"))
