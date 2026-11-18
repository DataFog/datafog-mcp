"""
The vault location is accepted from the launcher, validated, and kept private.

Only the plumbing exists: nothing reads from or writes to the directory. The
agent learns whether a vault is configured, never where it is.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import __main__ as cli
from datafog_mcp import api, paths, policy, server
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

    An explicit output path is refused by the path check. A policy whose copy
    directory is the vault is refused when it is loaded, before any path is
    looked at.
    """
    vault = _vault_with_entry(tmp_path, monkeypatch)
    source = tmp_path / "input.txt"
    source.write_text("contact avery@example.com", encoding="utf-8")
    shortcut = tmp_path / "shortcut"
    shortcut.symlink_to(vault, target_is_directory=True)
    arguments: dict[str, Any] = {"path": str(source)}
    if route == "output-path":
        arguments["output_path"] = str(vault / "copy.txt")
    elif route == "output-symlink":
        arguments["output_path"] = str(shortcut / "copy.txt")
    else:
        location = tmp_path / "policy.toml"
        location.write_text(
            f'version = 1\n[output]\ndirectory = "{vault.as_posix()}"\n', encoding="utf-8"
        )
        monkeypatch.setattr(policy, "POLICY_FILE", location)

    with pytest.raises(ToolError) as refused:
        call(tool, **arguments)

    _assert_refused(refused.value)
    assert sorted(item.name for item in vault.iterdir()) == ["entry.txt"]
    assert source.read_text(encoding="utf-8") == "contact avery@example.com"


def _policy_naming_the_vault(
    setting: str, route: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """
    Write a policy whose copy directory or scope folder leads to the vault.

    Parameters:
      setting: output, for the copy directory, or scope, for a scope folder.
      route: How the policy path reaches the vault.
      tmp_path: Holds the vault, the links, and the policy.
      monkeypatch: Configures the vault and the policy location.
    Returns:
      The vault directory.
    """
    vault = _vault_with_entry(tmp_path, monkeypatch)
    (vault / "inner").mkdir()
    (tmp_path / "shortcut").symlink_to(vault, target_is_directory=True)
    (tmp_path / "deep").symlink_to(vault / "inner", target_is_directory=True)
    named = {
        "vault": vault,
        "inside": vault / "inner",
        "symlink": tmp_path / "shortcut",
        "symlink-inside": tmp_path / "deep",
        "through-symlink": tmp_path / "shortcut" / "inner",
        "missing-inside": vault / "later",
    }[route]
    body = (
        f'[output]\ndirectory = "{named.as_posix()}"\n'
        if setting == "output"
        else f'[scope]\nfolders = ["{named.as_posix()}"]\n'
    )
    location = tmp_path / "policy.toml"
    location.write_text("version = 1\n" + body, encoding="utf-8")
    monkeypatch.setattr(policy, "POLICY_FILE", location)
    return vault


# A copy directory must exist, so only a scope folder can be a missing one.
POLICY_ROUTES = [
    (setting, route)
    for setting in ("output", "scope")
    for route in ("vault", "inside", "symlink", "symlink-inside", "through-symlink")
] + [("scope", "missing-inside")]
POLICY_REFUSALS = {
    "output": "output directory is inside the application vault directory",
    "scope": "scanning scope folder is inside the application vault directory",
}


@pytest.mark.parametrize(("setting", "route"), POLICY_ROUTES)
def test_policy_naming_the_vault_is_refused_everywhere(
    setting: str,
    route: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    A policy may not point its copy directory or a scope folder at the vault.

    datafog_policy reports both settings, and the file tools refuse paths
    inside the vault, so a policy naming the vault would let an agent put the
    two together. The policy is unusable instead: every tool, the owner
    command, and the Python interface refuse it with the same message.
    """
    vault = _policy_naming_the_vault(setting, route, tmp_path, monkeypatch)
    source = tmp_path / "input.txt"
    source.write_text("contact avery@example.com", encoding="utf-8")
    expected = POLICY_REFUSALS[setting]
    messages: list[str] = []

    with pytest.raises(api.PolicyFileError) as through_api:
        api.load_policy()
    messages.append(str(through_api.value))
    for tool in ("datafog_policy", *FILE_TOOLS):
        with pytest.raises(ToolError) as through_tool:
            call(tool, **({} if tool == "datafog_policy" else {"path": str(source)}))
        messages.append(str(through_tool.value))
    monkeypatch.setattr("sys.argv", ["datafog-mcp", "policy"])
    with pytest.raises(SystemExit) as through_cli:
        cli.main()

    assert messages == [expected] * 6
    assert str(through_cli.value) == f"datafog-mcp: {expected}"
    printed = capsys.readouterr()
    for text in (*messages, str(through_cli.value), printed.out, printed.err):
        assert VAULT_NAME not in text
        assert str(tmp_path) not in text
        assert "shortcut" not in text
    assert sorted(item.name for item in vault.iterdir()) == ["entry.txt", "inner"]
    assert not (tmp_path / "input_redacted.txt").exists()


def test_policy_paths_beside_or_around_the_vault_are_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the vault and what is inside it are refused as policy paths."""
    _vault_with_entry(tmp_path, monkeypatch)
    beside = tmp_path / f"{VAULT_NAME}-copies"
    beside.mkdir()
    location = tmp_path / "policy.toml"
    location.write_text(
        f'version = 1\n[output]\ndirectory = "{beside.as_posix()}"\n'
        f'[scope]\nfolders = ["{tmp_path.as_posix()}", "{beside.as_posix()}"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(policy, "POLICY_FILE", location)

    current = api.load_policy()

    assert current.directory == beside.resolve()
    assert current.scope_folders == (tmp_path.resolve(), beside.resolve())


def test_policy_paths_are_not_checked_against_an_absent_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the variable, the same policy loads as before."""
    vault = _policy_naming_the_vault("output", "vault", tmp_path, monkeypatch)
    monkeypatch.delenv(VAULT_DIR_VAR)

    assert api.load_policy().directory == vault.resolve()


@pytest.mark.parametrize("setting", ["output", "scope"])
def test_policy_paths_fail_closed_on_an_unusable_vault(
    setting: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A vault setting that cannot be used cannot clear a policy path either."""
    _policy_naming_the_vault(setting, "vault", tmp_path, monkeypatch)
    monkeypatch.setenv(VAULT_DIR_VAR, f"relative/{VAULT_NAME}")

    with pytest.raises(api.PolicyFileError, match="must be an absolute path") as refused:
        api.load_policy()

    assert VAULT_DIR_VAR in str(refused.value)
    assert VAULT_NAME not in str(refused.value)
    assert str(tmp_path) not in str(refused.value)


COVERED_ROOT = (
    f"${VAULT_DIR_VAR} is an allowed root or contains one, so every path would be refused"
)


def _vault_covering_a_root(kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Configure a vault that is an allowed root or contains one.

    Parameters:
      kind: How the vault relates to the root.
      tmp_path: Holds the vault and the root.
      monkeypatch: Sets both environment variables, or the home directory.
    """
    vault = tmp_path / VAULT_NAME
    vault.mkdir()
    (vault / "exports").mkdir()
    (tmp_path / "shortcut").symlink_to(vault, target_is_directory=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    if kind == "home-default":
        # No roots configured: the default root is the home directory.
        monkeypatch.delenv("DATAFOG_MCP_ALLOWED_ROOTS")
        monkeypatch.setattr(paths, "ROOTS_FILE", tmp_path / "absent" / "allowed_roots")
        monkeypatch.setenv("HOME", str(vault))
        monkeypatch.setenv(VAULT_DIR_VAR, "~")
        return
    root, location = {
        "same": (vault, vault),
        "contains": (vault / "exports", vault),
        "root-symlink": (tmp_path / "shortcut", vault),
        "vault-symlink": (vault, tmp_path / "shortcut"),
        "filesystem-root": (elsewhere, Path(vault.anchor)),
        "one-of-several": (vault / "exports", vault),
    }[kind]
    roots = [elsewhere, root] if kind == "one-of-several" else [root]
    monkeypatch.setenv("DATAFOG_MCP_ALLOWED_ROOTS", os.pathsep.join(str(item) for item in roots))
    monkeypatch.setenv(VAULT_DIR_VAR, str(location))


COVERING = [
    "same",
    "contains",
    "root-symlink",
    "vault-symlink",
    "filesystem-root",
    "one-of-several",
    "home-default",
]


@pytest.mark.parametrize("kind", COVERING)
def test_server_refuses_to_start_when_the_vault_covers_an_allowed_root(
    kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    A vault that is a root, or contains one, would refuse every path.

    The server stops before serving, and the owner command and datafog_policy
    refuse the same way, so the listed roots can never be read beside
    vault refusals to work out where the vault is.
    """
    _vault_covering_a_root(kind, tmp_path, monkeypatch)
    started: list[bool] = []
    monkeypatch.setattr(server.mcp, "run", lambda **_options: started.append(True))

    with pytest.raises(SystemExit) as stopped:
        server.run_server()
    with pytest.raises(ToolError) as through_tool:
        call("datafog_policy")
    monkeypatch.setattr("sys.argv", ["datafog-mcp", "policy"])
    with pytest.raises(SystemExit) as through_cli:
        cli.main()

    assert started == []
    assert str(stopped.value) == f"datafog-mcp: {COVERED_ROOT}"
    assert str(through_cli.value) == f"datafog-mcp: {COVERED_ROOT}"
    assert str(through_tool.value) == COVERED_ROOT
    printed = capsys.readouterr()
    for text in (COVERED_ROOT, printed.out, printed.err):
        assert VAULT_NAME not in text
        assert str(tmp_path) not in text


def _requests_for_every_path_argument(inside: Path, outside: Path) -> dict[str, dict[str, Any]]:
    """
    Build one request per tool and path argument.

    Parameters:
      inside: A file under the allowed root.
      outside: A path under no allowed root.

    Returns:
      Request arguments by an id of the form tool-argument-location.
    """
    requests: dict[str, dict[str, Any]] = {"datafog_policy-no-path": {}}
    for tool in ["datafog_policy", *FILE_TOOLS]:
        requests[f"{tool}-path-inside"] = {"path": str(inside)}
        requests[f"{tool}-path-outside"] = {"path": str(outside)}
    for tool in WRITE_TOOLS:
        requests[f"{tool}-output-inside"] = {
            "path": str(inside),
            "output_path": str(inside.with_name("copy.txt")),
        }
        requests[f"{tool}-output-outside"] = {
            "path": str(inside),
            "output_path": str(outside.with_name("copy.txt")),
        }
    return requests


REQUEST_IDS = sorted(_requests_for_every_path_argument(Path("/in/a"), Path("/out/b")))


@pytest.mark.parametrize("request_id", REQUEST_IDS)
@pytest.mark.parametrize("kind", COVERING)
def test_no_tool_names_a_root_that_the_vault_covers(
    kind: str, request_id: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Every tool and path argument gets the same content-free refusal.

    The roots can change after startup, so the startup check is repeated on
    each request. A refusal that listed the allowed roots, as the ordinary
    outside-roots refusal does, would name a directory inside the vault.
    """
    _vault_covering_a_root(kind, tmp_path, monkeypatch)
    inside = tmp_path / VAULT_NAME / "exports" / "input.txt"
    inside.write_text("contact avery@example.com", encoding="utf-8")
    outside = Path(tmp_path.anchor) / "etc" / "hostname"
    arguments = _requests_for_every_path_argument(inside, outside)[request_id]
    tool = request_id.split("-")[0]

    with pytest.raises(ToolError) as refused:
        call(tool, **arguments)

    message = str(refused.value)
    assert message == COVERED_ROOT
    for hidden in (VAULT_NAME, str(tmp_path), "exports", "elsewhere", "shortcut", "outside"):
        assert hidden not in message
    assert sorted(item.name for item in inside.parent.iterdir()) == ["input.txt"]


@pytest.mark.parametrize("kind", COVERING)
def test_python_interface_names_no_root_that_the_vault_covers(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The public resolve and read functions refuse the same way."""
    _vault_covering_a_root(kind, tmp_path, monkeypatch)
    inside = tmp_path / VAULT_NAME / "exports" / "input.txt"
    inside.write_text("contact avery@example.com", encoding="utf-8")
    outside = Path(tmp_path.anchor) / "etc" / "hostname"

    for path in (inside, outside):
        with pytest.raises(api.RootPolicyError) as resolved:
            api.resolve_input(str(path))
        assert str(resolved.value) == COVERED_ROOT
        with pytest.raises(api.RootPolicyError) as read:
            api.read_text_file(str(path), api.DEFAULT_MAX_BYTES)
        assert str(read.value) == COVERED_ROOT
        with pytest.raises(paths.PolicyError) as written:
            paths.resolve_output(str(path.with_name("copy.txt")), inside)
        assert str(written.value) == COVERED_ROOT


def test_roots_moved_inside_the_vault_after_startup_are_not_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The reported case: the server started cleanly, then the roots changed.

    The vault is apart from the root at startup. The roots file is then
    edited to a directory inside the vault, and the next requests arrive.
    """
    vault = tmp_path / VAULT_NAME
    inner = vault / "inner"
    inner.mkdir(parents=True)
    start = tmp_path / "allowed"
    start.mkdir()
    roots_file = tmp_path / "config" / "allowed_roots"
    roots_file.parent.mkdir()
    roots_file.write_text(f"{start}\n", encoding="utf-8")
    monkeypatch.delenv("DATAFOG_MCP_ALLOWED_ROOTS")
    monkeypatch.setattr(paths, "ROOTS_FILE", roots_file)
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))
    started: list[bool] = []
    monkeypatch.setattr(server.mcp, "run", lambda **_options: started.append(True))
    server.run_server()
    assert started == [True]
    assert call("datafog_policy")["allowed_roots"] == [str(start)]

    roots_file.write_text(f"{inner}\n", encoding="utf-8")

    outside = str(Path(tmp_path.anchor) / "etc" / "hostname")
    attempts: list[tuple[str, dict[str, Any]]] = [
        ("datafog_policy", {}),
        ("datafog_policy", {"path": outside}),
        *((tool, {"path": outside}) for tool in FILE_TOOLS),
        *((tool, {"path": str(inner / "input.txt")}) for tool in FILE_TOOLS),
    ]
    for tool, arguments in attempts:
        with pytest.raises(ToolError) as refused:
            call(tool, **arguments)
        message = str(refused.value)
        assert message == COVERED_ROOT, tool
        assert VAULT_NAME not in message
        assert "inner" not in message
        assert str(tmp_path) not in message


def _refusal(tool: str, **arguments: Any) -> str:
    """Return the refusal a tool gives, as the caller sees it."""
    with pytest.raises(ToolError) as refused:
        call(tool, **arguments)
    return str(refused.value)


@pytest.mark.parametrize("tool", [*FILE_TOOLS, "datafog_policy"])
@pytest.mark.parametrize("target", ["entry", "directory", "missing"])
def test_a_guess_outside_the_roots_cannot_confirm_the_vault(
    tool: str, target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A path inside the vault and one beside it get the same refusal.

    The vault is apart from every root. A caller who guesses its location
    receives the ordinary outside-roots refusal, naming the path exactly as
    they wrote it, so the answer is the one any wrong guess would get.
    """
    root = tmp_path / "allowed"
    root.mkdir()
    vault = tmp_path / VAULT_NAME
    other = tmp_path / "not-a-vault"
    for directory in (vault, other):
        directory.mkdir()
        (directory / "entry.txt").write_text(f"token-1 = {ENTRY}\n", encoding="utf-8")
    monkeypatch.setenv("DATAFOG_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))
    suffix = {"entry": "entry.txt", "directory": "", "missing": "absent/later.txt"}[target]

    guessed = _refusal(tool, path=str(vault / suffix))
    control = _refusal(tool, path=str(other / suffix))

    assert "outside the allowed roots" in guessed
    assert "vault" not in guessed.replace(VAULT_NAME, "")
    assert guessed.replace(VAULT_NAME, "not-a-vault") == control
    assert ENTRY not in guessed


@pytest.mark.parametrize("tool", [*FILE_TOOLS, "datafog_policy"])
@pytest.mark.parametrize("through", ["file-link", "directory-link"])
def test_a_link_outside_the_roots_cannot_confirm_the_vault(
    tool: str, through: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A link into the vault and a link beside it get the same refusal.

    The refusal names the link as the caller wrote it and never the location
    it resolves to, so it is the same text for both and shows neither target.
    """
    root = tmp_path / "allowed"
    root.mkdir()
    vault = tmp_path / VAULT_NAME
    other = tmp_path / "not-a-vault"
    refusals = []
    for name, directory in (("first", vault), ("second", other)):
        directory.mkdir()
        (directory / "entry.txt").write_text(f"token-1 = {ENTRY}\n", encoding="utf-8")
        if through == "file-link":
            link = root / f"{name}.txt"
            link.symlink_to(directory / "entry.txt")
        else:
            (root / name).symlink_to(directory, target_is_directory=True)
            link = root / name / "entry.txt"
        refusals.append((name, link))
    monkeypatch.setenv("DATAFOG_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))

    into_vault, beside = (_refusal(tool, path=str(link)) for _name, link in refusals)

    assert "resolves to a location outside the allowed roots" in into_vault
    assert into_vault.replace("first", "second") == beside
    for message in (into_vault, beside):
        assert VAULT_NAME not in message
        assert "not-a-vault" not in message
        assert "vault" not in message


@pytest.mark.parametrize("tool", WRITE_TOOLS)
def test_an_output_guess_outside_the_roots_cannot_confirm_the_vault(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An output_path inside the vault is refused like any other outside the roots."""
    root = tmp_path / "allowed"
    root.mkdir()
    source = root / "input.txt"
    source.write_text("contact avery@example.com", encoding="utf-8")
    vault = tmp_path / VAULT_NAME
    other = tmp_path / "not-a-vault"
    vault.mkdir()
    other.mkdir()
    monkeypatch.setenv("DATAFOG_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))

    guessed = _refusal(tool, path=str(source), output_path=str(vault / "copy.txt"))
    control = _refusal(tool, path=str(source), output_path=str(other / "copy.txt"))

    assert "outside the allowed roots" in guessed
    assert guessed.replace(VAULT_NAME, "not-a-vault") == control
    assert list(vault.iterdir()) == []
    assert list(other.iterdir()) == []


def test_python_interface_gives_a_vault_guess_the_ordinary_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """resolve_input and read_text_file answer a guess as the tools do."""
    root = tmp_path / "allowed"
    root.mkdir()
    vault = tmp_path / VAULT_NAME
    vault.mkdir()
    monkeypatch.setenv("DATAFOG_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))
    guess = vault / "entry.txt"
    expected = f"{guess} is outside the allowed roots: {root}"

    with pytest.raises(api.PathNotAllowed) as resolved:
        api.resolve_input(str(guess))
    with pytest.raises(api.PathNotAllowed) as read:
        api.read_text_file(str(guess), api.DEFAULT_MAX_BYTES)

    assert str(resolved.value) == expected
    assert str(read.value) == expected
    assert not isinstance(resolved.value, api.RootPolicyError)


def test_a_vault_path_is_refused_when_no_roots_are_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With an empty roots policy a vault path is refused like every other path."""
    vault = tmp_path / VAULT_NAME
    vault.mkdir()
    other = tmp_path / "not-a-vault"
    other.mkdir()
    monkeypatch.setenv("DATAFOG_MCP_ALLOWED_ROOTS", "")
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))

    guessed = _refusal("datafog_scan", path=str(vault / "entry.txt"))
    control = _refusal("datafog_scan", path=str(other / "entry.txt"))

    assert "lists no allowed roots" in guessed
    assert guessed.replace(VAULT_NAME, "not-a-vault") == control


@pytest.mark.parametrize("kind", ["inside-root", "outside-roots", "no-roots", "broken-roots"])
def test_server_starts_when_the_vault_covers_no_allowed_root(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A vault inside a root, or apart from every root, is the ordinary case."""
    root = tmp_path / "allowed"
    root.mkdir()
    vault = (root if kind == "inside-root" else tmp_path) / VAULT_NAME
    monkeypatch.setenv(VAULT_DIR_VAR, str(vault))
    monkeypatch.setenv(
        "DATAFOG_MCP_ALLOWED_ROOTS",
        {"no-roots": "", "broken-roots": "relative/root"}.get(kind, str(root)),
    )
    started: list[bool] = []
    monkeypatch.setattr(server.mcp, "run", lambda **_options: started.append(True))

    server.run_server()

    assert started == [True]


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
