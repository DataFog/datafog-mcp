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
from datafog_mcp import api, policy, server
from datafog_mcp.server import mcp
from datafog_mcp.vault import VAULT_DIR_VAR, VaultConfigError, vault_configured, vault_dir

# Distinctive, so a leaked location is easy to spot in any output.
VAULT_NAME = "kept-private-vault"
# What a vault entry might hold; synthetic, on a reserved example domain.
ENTRY = "vaulted-person@example.com"

FILE_TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]
WRITE_TOOLS = ["datafog_redact", "datafog_mask", "datafog_remove"]


def call(tool: str, **arguments: Any) -> dict[str, Any]:
    """Invoke the real server through an in-memory MCP client."""

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, arguments)
            assert VAULT_NAME not in str(result.content)
            assert ENTRY not in str(result.content)
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
    """The vault is application storage and may sit outside every root."""
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


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_unusable_vault_refuses_file_tools(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A vault setting that cannot be used refuses every path.

    The server will not start in this state. A program using the Python
    interface can still reach it, and must not read a file the vault setting
    was meant to protect.
    """
    source = tmp_path / "input.txt"
    source.write_text("contact avery@example.com", encoding="utf-8")
    monkeypatch.setenv(VAULT_DIR_VAR, f"relative/{VAULT_NAME}")

    with pytest.raises(ToolError, match="must be an absolute path") as refused:
        call(tool, path=str(source))
    with pytest.raises(api.RootPolicyError, match="must be an absolute path"):
        api.resolve_input(str(source))

    assert VAULT_DIR_VAR in str(refused.value)
    assert VAULT_NAME not in str(refused.value)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["input.txt"]


def _vault_with_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Configure a vault inside the allowed roots holding one synthetic entry."""
    vault = tmp_path / VAULT_NAME
    vault.mkdir()
    (vault / "entry.txt").write_text(f"token-1 = {ENTRY}\n", encoding="utf-8")
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))
    return vault


def _assert_refused(error: BaseException) -> None:
    """A vault refusal says what happened and nothing about the vault."""
    message = str(error)
    assert "inside the application vault directory" in message
    assert VAULT_NAME not in message
    assert ENTRY not in message
    assert "entry.txt" not in message


@pytest.mark.parametrize("tool", [*FILE_TOOLS, "datafog_policy"])
@pytest.mark.parametrize("target", ["entry", "directory", "missing", "symlink-file", "symlink-dir"])
def test_paths_inside_the_vault_are_refused(
    tool: str, target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    No tool reads the vault, by its own path or through a link.

    The vault sits inside an allowed root here, so only the vault refusal
    stands between the tools and its entries.
    """
    vault = _vault_with_entry(tmp_path, monkeypatch)
    links = tmp_path / "links"
    links.mkdir()
    if target == "entry":
        path = vault / "entry.txt"
    elif target == "directory":
        path = vault
    elif target == "missing":
        path = vault / "absent" / "later.txt"
    elif target == "symlink-file":
        path = links / "notes.txt"
        path.symlink_to(vault / "entry.txt")
    else:
        (links / "shortcut").symlink_to(vault, target_is_directory=True)
        path = links / "shortcut" / "entry.txt"

    with pytest.raises(ToolError) as refused:
        call(tool, path=str(path))

    _assert_refused(refused.value)
    assert sorted(item.name for item in vault.iterdir()) == ["entry.txt"]
    assert sorted(item.name for item in tmp_path.iterdir()) == sorted(["links", VAULT_NAME])


def test_python_interface_refuses_vault_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The public resolve and read functions apply the same refusal."""
    vault = _vault_with_entry(tmp_path, monkeypatch)
    link = tmp_path / "notes.txt"
    link.symlink_to(vault / "entry.txt")

    for path in (vault / "entry.txt", vault, link):
        with pytest.raises(api.PathNotAllowed) as resolved:
            api.resolve_input(str(path))
        _assert_refused(resolved.value)
        with pytest.raises(api.PathNotAllowed) as read:
            api.read_text_file(str(path), api.DEFAULT_MAX_BYTES)
        _assert_refused(read.value)


def test_a_vault_that_does_not_exist_yet_is_still_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal goes by location, so it holds before the vault is created."""
    vault = tmp_path / VAULT_NAME
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))

    with pytest.raises(ToolError) as refused:
        call("datafog_scan", path=str(vault / "entry.txt"))

    _assert_refused(refused.value)
    assert not vault.exists()


@pytest.mark.parametrize("tool", WRITE_TOOLS)
@pytest.mark.parametrize("route", ["output-path", "output-symlink", "policy-directory"])
def test_copies_are_never_written_into_the_vault(
    tool: str, route: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    No write lands in the vault, whichever way the destination is chosen.

    The owner's copy directory is pointed at the vault for every route, so the
    usual same-directory rule would allow the write and only the vault
    refusal prevents it.
    """
    vault = _vault_with_entry(tmp_path, monkeypatch)
    source = tmp_path / "input.txt"
    source.write_text("contact avery@example.com", encoding="utf-8")
    shortcut = tmp_path / "shortcut"
    shortcut.symlink_to(vault, target_is_directory=True)
    location = tmp_path / "policy.toml"
    location.write_text(
        f'version = 1\n[output]\ndirectory = "{vault.as_posix()}"\n', encoding="utf-8"
    )
    monkeypatch.setattr(policy, "POLICY_FILE", location)
    arguments: dict[str, Any] = {"path": str(source)}
    if route == "output-path":
        arguments["output_path"] = str(vault / "copy.txt")
    elif route == "output-symlink":
        arguments["output_path"] = str(shortcut / "copy.txt")

    with pytest.raises(ToolError) as refused:
        call(tool, **arguments)

    _assert_refused(refused.value)
    assert sorted(item.name for item in vault.iterdir()) == ["entry.txt"]
    assert source.read_text(encoding="utf-8") == "contact avery@example.com"


@pytest.mark.parametrize("tool", FILE_TOOLS)
def test_files_beside_the_vault_are_unaffected(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the vault is refused, not its neighbours or similarly named paths."""
    _vault_with_entry(tmp_path, monkeypatch)
    lookalike = tmp_path / f"{VAULT_NAME}-export"
    lookalike.mkdir()
    source = lookalike / "input.txt"
    source.write_text("contact avery@example.com", encoding="utf-8")

    async def run() -> dict[str, Any]:
        # Not the shared helper: this path legitimately contains the vault's
        # name as a prefix of a different directory.
        async with Client(mcp) as client:
            result = await client.call_tool(tool, {"path": str(source)})
            assert result.structured_content is not None
            return result.structured_content

    result = asyncio.run(run())

    assert result["counts"] == {"EMAIL": 1}
    assert "vault_configured" not in result
    assert ENTRY not in str(result)


@pytest.mark.parametrize("kind", sorted(INVALID))
def test_server_refuses_to_start_with_an_unusable_vault(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing is served: the transport is never started."""
    build, reason = INVALID[kind]
    monkeypatch.setenv(VAULT_DIR_VAR, build(tmp_path))
    started: list[bool] = []
    monkeypatch.setattr(server.mcp, "run", lambda **_options: started.append(True))

    with pytest.raises(SystemExit) as stopped:
        server.run_server()

    message = str(stopped.value)
    assert message.startswith("datafog-mcp: ")
    assert reason in message
    assert VAULT_DIR_VAR in message
    assert VAULT_NAME not in message
    assert str(tmp_path) not in message
    assert started == []


@pytest.mark.parametrize("configured", [True, False])
def test_server_starts_with_a_usable_or_absent_vault(
    configured: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The startup check only stops an unusable setting."""
    if configured:
        monkeypatch.setenv(VAULT_DIR_VAR, str(tmp_path / VAULT_NAME))
    started: list[bool] = []
    monkeypatch.setattr(server.mcp, "run", lambda **_options: started.append(True))

    server.run_server()

    assert started == [True]


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
