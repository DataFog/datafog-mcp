"""
The vault location is accepted from the launcher, validated, and kept private.

Only the plumbing exists: nothing reads from or writes to the directory. The
agent learns whether a vault is configured, never where it is.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import __main__ as cli
from datafog_mcp.server import mcp
from datafog_mcp.vault import VAULT_DIR_VAR, VaultConfigError, vault_configured, vault_dir

# Distinctive, so a leaked location is easy to spot in any output.
VAULT_NAME = "kept-private-vault"


def call(tool: str, **arguments: Any) -> dict[str, Any]:
    """Invoke the real server through an in-memory MCP client."""

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, arguments)
            assert VAULT_NAME not in str(result.content)
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


def test_unset_means_no_vault() -> None:
    """Without the variable there is no vault and no default location."""
    assert vault_dir() is None
    assert vault_configured() is False
    assert call("datafog_policy")["vault_configured"] is False


def test_configured_vault_is_reported_only_as_a_boolean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent learns that a vault exists, and nothing about where."""
    vault = tmp_path / VAULT_NAME
    vault.mkdir()
    (vault / "entry").write_text("synthetic vault entry", encoding="utf-8")
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))

    result = call("datafog_policy")

    assert vault_dir() == vault.resolve()
    assert result["vault_configured"] is True
    assert VAULT_NAME not in json.dumps(result)
    assert "synthetic vault entry" not in json.dumps(result)


def test_vault_may_not_exist_yet_and_is_not_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validation never touches the filesystem beyond inspecting it."""
    vault = tmp_path / "missing" / VAULT_NAME
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))

    assert vault_dir() == vault.resolve()
    assert call("datafog_policy")["vault_configured"] is True
    assert not vault.exists()
    assert not vault.parent.exists()


def test_home_relative_vault_is_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A leading ~ is expanded, as for roots and policy paths."""
    monkeypatch.setenv(VAULT_DIR_VAR, f"~/{VAULT_NAME}")

    assert vault_dir() == (Path.home() / VAULT_NAME).resolve()


def test_vault_need_not_be_inside_allowed_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Roots bound the files the tools touch, not application storage."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    vault = tmp_path / VAULT_NAME
    vault.mkdir()
    monkeypatch.setenv("DATAFOG_MCP_ALLOWED_ROOTS", str(allowed))
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))

    assert call("datafog_policy")["vault_configured"] is True


def _credential_link(tmp_path: Path) -> str:
    """Build a harmless-looking path that resolves into a credential directory."""
    target = tmp_path / ".ssh" / VAULT_NAME
    target.mkdir(parents=True)
    link = tmp_path / "storage"
    link.symlink_to(target, target_is_directory=True)
    return str(link)


def _file_in_place(tmp_path: Path) -> str:
    """Put a regular file where the vault directory should be."""
    path = tmp_path / VAULT_NAME
    path.write_text("not a directory", encoding="utf-8")
    return str(path)


def _under_a_file(tmp_path: Path) -> str:
    """Name a location beneath a regular file, which can never be a directory."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    return str(blocker / VAULT_NAME)


INVALID = {
    "unknown-user": (
        lambda tmp_path: f"~datafog-no-such-user/{VAULT_NAME}",
        "cannot be resolved",
    ),
    "under-file": (_under_a_file, "cannot be inspected"),
    "empty": (lambda tmp_path: "", "names no directory"),
    "blank": (lambda tmp_path: "   ", "names no directory"),
    "relative": (lambda tmp_path: f"relative/{VAULT_NAME}", "must be an absolute path"),
    "credential": (lambda tmp_path: str(tmp_path / ".aws" / VAULT_NAME), "credential directory"),
    "credential-case": (
        lambda tmp_path: str(tmp_path / ".SSH" / VAULT_NAME),
        "credential directory",
    ),
    "credential-symlink": (_credential_link, "credential directory"),
    "file": (_file_in_place, "must name a directory"),
}


@pytest.mark.parametrize("kind", sorted(INVALID))
def test_unusable_vault_is_an_error_that_withholds_the_location(
    kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    A set but unusable value fails loudly, everywhere it is reported.

    Reading it as unset would silently turn the vault off. The message names
    the variable and the problem, never the value.
    """
    build, reason = INVALID[kind]
    monkeypatch.setenv(VAULT_DIR_VAR, build(tmp_path))

    with pytest.raises(VaultConfigError, match=reason) as direct:
        vault_dir()
    with pytest.raises(VaultConfigError):
        vault_configured()
    with pytest.raises(ToolError, match=reason) as through_tool:
        call("datafog_policy")
    monkeypatch.setattr("sys.argv", ["datafog-mcp", "policy"])
    with pytest.raises(SystemExit) as through_cli:
        cli.main()

    for message in (str(direct.value), str(through_tool.value), str(through_cli.value)):
        assert VAULT_DIR_VAR in message
        assert VAULT_NAME not in message
        assert str(tmp_path) not in message
    assert VAULT_NAME not in capsys.readouterr().out


@pytest.mark.parametrize("configured", [True, False])
def test_owner_cli_reports_whether_a_vault_is_configured(
    configured: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The owner command names the variable, not the directory."""
    if configured:
        monkeypatch.setenv(VAULT_DIR_VAR, str(tmp_path / VAULT_NAME))
    monkeypatch.setattr("sys.argv", ["datafog-mcp", "policy"])

    cli.main()

    output = capsys.readouterr().out
    expected = f"configured by ${VAULT_DIR_VAR}" if configured else "not configured"
    assert f"Application vault: {expected}" in output
    assert VAULT_NAME not in output


@pytest.mark.parametrize(
    "tool", ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]
)
def test_file_tools_do_not_consult_the_vault(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Scans and writes neither need nor mention the vault.

    Nothing uses the vault yet, so an unusable location is reported by
    datafog_policy and the owner command without stopping file tools.
    """
    source = tmp_path / "input.txt"
    source.write_text("contact avery@example.com", encoding="utf-8")
    monkeypatch.setenv(VAULT_DIR_VAR, f"relative/{VAULT_NAME}")

    result = call(tool, path=str(source))

    assert result["counts"] == {"EMAIL": 1}
    assert "vault_configured" not in result


def test_no_tool_was_added_for_the_vault() -> None:
    """The vault is configuration only: the tool list is unchanged."""

    async def names() -> set[str]:
        async with Client(mcp) as client:
            return {tool.name for tool in await client.list_tools()}

    assert asyncio.run(names()) == {
        "datafog_policy",
        "datafog_scan",
        "datafog_redact",
        "datafog_mask",
        "datafog_remove",
    }
