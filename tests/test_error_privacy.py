"""
The no-values contract holds when tools fail, not only when they succeed.

Every tool promises that no response carries a matched value. An engine or
filesystem exception whose message holds file content would break that
promise through the error channel, reaching the client and the server's
stderr. These tests inject a sentinel into each failure point and check both.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.client import CallToolResult
from fastmcp.exceptions import ToolError

from datafog_mcp import policy, server
from datafog_mcp.server import mcp
from datafog_mcp.vault import VAULT_DIR_VAR

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


@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize("route", ["direct", "symlink"])
def test_vault_refusal_carries_no_vault_detail(
    tool: str,
    route: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Refusing a path inside the vault reveals neither its location nor contents.

    The sentinel is both a vault entry's content and part of the vault's
    directory name, so a leak of either through the response, stderr, or the
    log is caught. Through a symlink, the requested path does not name the
    vault, so only the refusal itself could.

    Parameters:
      tool: The tool under test.
      route: Whether the vault is addressed by its own path or through a link.
      tmp_path: Holds the vault and the link.
      monkeypatch: Configures the vault location.
      capfd: Captures stdout and stderr.
      caplog: Captures log records.
    """
    vault = tmp_path / f"vault-{SENTINEL}"
    vault.mkdir()
    entry = vault / "entry.txt"
    entry.write_text(f"token-1 = {SENTINEL}\n", encoding="utf-8")
    link = tmp_path / "notes.txt"
    link.symlink_to(entry)
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))

    with pytest.raises(ToolError, match="inside the application vault directory") as excinfo:
        _call(tool, path=str(entry if route == "direct" else link))

    captured = capfd.readouterr()
    assert SENTINEL not in str(excinfo.value)
    assert SENTINEL not in captured.out
    assert SENTINEL not in captured.err
    assert SENTINEL not in caplog.text


@pytest.mark.parametrize("tool", ["datafog_policy", *ALL_TOOLS])
@pytest.mark.parametrize("setting", ["output", "scope"])
@pytest.mark.parametrize("route", ["direct", "symlink"])
def test_policy_naming_the_vault_carries_no_vault_detail(
    tool: str,
    setting: str,
    route: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    A policy whose copy directory or scope folder is the vault reveals nothing.

    datafog_policy would otherwise return the directory, and a write would be
    refused as inside the vault, which together locate it. The sentinel is in
    the vault's name and in the link that leads to it, so the policy value and
    the resolved location are both caught in the response, stderr, and the log.

    Parameters:
      tool: The tool under test.
      setting: Whether the copy directory or a scope folder names the vault.
      route: Whether the policy names the vault itself or a link to it.
      tmp_path: Holds the vault, the link, and the policy.
      monkeypatch: Configures the vault and the policy location.
      capfd: Captures stdout and stderr.
      caplog: Captures log records.
    """
    vault = tmp_path / f"vault-{SENTINEL}"
    vault.mkdir()
    link = tmp_path / f"link-{SENTINEL}"
    link.symlink_to(vault, target_is_directory=True)
    named = (vault if route == "direct" else link).as_posix()
    body = (
        f'[output]\ndirectory = "{named}"\n'
        if setting == "output"
        else f'[scope]\nfolders = ["{named}"]\n'
    )
    location = tmp_path / "policy.toml"
    location.write_text("version = 1\n" + body, encoding="utf-8")
    monkeypatch.setattr(policy, "POLICY_FILE", location)
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))
    source = tmp_path / "contacts.txt"
    source.write_text("contact jack.smith@example.com\n", encoding="utf-8")
    arguments = {} if tool == "datafog_policy" else {"path": str(source)}

    with pytest.raises(ToolError, match="is inside the application vault directory") as excinfo:
        _call(tool, **arguments)

    captured = capfd.readouterr()
    assert SENTINEL not in str(excinfo.value)
    assert SENTINEL not in captured.out
    assert SENTINEL not in captured.err
    assert SENTINEL not in caplog.text
    assert list(vault.iterdir()) == []


@pytest.mark.parametrize("command", [[], ["policy"]])
def test_startup_refusal_for_a_vault_covering_a_root_names_no_location(
    command: list[str], tmp_path: Path
) -> None:
    """
    A vault that is the allowed root stops the real entry point, privately.

    Runs in a child process with the default root, the home directory, and
    the vault set to that same directory. The sentinel is in its name.

    Parameters:
      command: The server itself, or the owner's policy command.
      tmp_path: Holds the home directory.
    """
    home = tmp_path / f"home-{SENTINEL}"
    home.mkdir()
    environment = {**os.environ, VAULT_DIR_VAR: "~", "HOME": str(home)}
    environment.pop("DATAFOG_MCP_ALLOWED_ROOTS", None)

    completed = subprocess.run(
        [sys.executable, "-m", "datafog_mcp", *command],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
        check=False,
    )

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr.strip() == (
        f"datafog-mcp: ${VAULT_DIR_VAR} is an allowed root or contains one, "
        "so every path would be refused"
    )
    assert SENTINEL not in completed.stderr


@pytest.mark.parametrize("value", [f"relative/{SENTINEL}", f"/tmp/.ssh/{SENTINEL}", ""])
def test_startup_refusal_names_the_variable_never_its_value(value: str, tmp_path: Path) -> None:
    """
    A server launched with an unusable vault location exits without leaking it.

    Runs the real entry point in a child process, as an MCP client would. It
    must stop with a nonzero status, say which variable is wrong on stderr,
    write nothing to stdout, where the protocol runs, and never repeat the
    value it was given.

    Parameters:
      value: An unusable vault location carrying the sentinel.
      tmp_path: A home directory with no configuration in it.
    """
    environment = {**os.environ, VAULT_DIR_VAR: value, "HOME": str(tmp_path)}

    completed = subprocess.run(
        [sys.executable, "-m", "datafog_mcp"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
        check=False,
    )

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr.strip().startswith(f"datafog-mcp: ${VAULT_DIR_VAR} ")
    assert SENTINEL not in completed.stderr
    assert "Traceback" not in completed.stderr
