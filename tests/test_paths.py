"""Tests for datafog_mcp.paths."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from datafog_mcp import paths
from datafog_mcp.paths import (
    ALLOWED_ROOTS_VAR,
    PathNotAllowed,
    allowed_roots,
    resolve_input,
    resolve_output,
)


def _set_roots(monkeypatch: pytest.MonkeyPatch, *roots: Path) -> None:
    """
    Point the policy at the given roots, overriding conftest.

    Parameters:
      monkeypatch: Sets the environment variable for one test.
      roots: Directories the server should be allowed to touch.
    """
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, os.pathsep.join(str(root) for root in roots))


def test_path_inside_a_root_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A file under a configured root resolves normally."""
    _set_roots(monkeypatch, tmp_path)
    target = tmp_path / "export.csv"

    assert resolve_input(str(target)) == target.resolve()


def test_path_outside_every_root_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory beside an allowed root is still outside it."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    _set_roots(monkeypatch, allowed)

    with pytest.raises(PathNotAllowed):
        resolve_input(str(tmp_path / "elsewhere" / "export.csv"))


def test_symlink_escaping_a_root_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A link inside a root is judged by where it points.

    Checking before resolution would let any allowed directory hand out
    access to the whole filesystem.
    """
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()

    secret = outside / "secret.csv"
    secret.write_text("x")
    link = allowed / "link.csv"
    link.symlink_to(secret)

    _set_roots(monkeypatch, allowed)

    with pytest.raises(PathNotAllowed):
        resolve_input(str(link))


def test_credential_directory_is_refused_inside_a_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Being inside an allowed root does not open .ssh."""
    _set_roots(monkeypatch, tmp_path)

    with pytest.raises(PathNotAllowed):
        resolve_input(str(tmp_path / ".ssh" / "id_ed25519"))


def test_several_roots_are_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every entry in the variable becomes a root."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    _set_roots(monkeypatch, first, second)

    target = second / "export.csv"

    assert resolve_input(str(target)) == target.resolve()
    assert set(allowed_roots()) == {first.resolve(), second.resolve()}


def test_tilde_in_the_variable_is_expanded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A root written as ~ resolves to the home directory."""
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, "~")

    assert allowed_roots() == (Path.home().resolve(),)


def test_unset_variable_falls_back_to_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With nothing configured the server may touch the user's files."""
    monkeypatch.delenv(ALLOWED_ROOTS_VAR, raising=False)
    monkeypatch.setattr(paths, "ROOTS_FILE", tmp_path / "absent")

    assert allowed_roots() == (Path.home().resolve(),)


def test_output_path_need_not_exist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A destination is resolved before anything is written to it."""
    _set_roots(monkeypatch, tmp_path)
    destination = tmp_path / "export_redacted.csv"

    assert resolve_output(str(destination)) == destination.resolve()


def test_output_outside_every_root_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Writes are held to the same policy as reads."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    _set_roots(monkeypatch, allowed)

    with pytest.raises(PathNotAllowed):
        resolve_output(str(tmp_path / "escape.csv"))


def _write_roots_file(monkeypatch: pytest.MonkeyPatch, path: Path, body: str) -> None:
    """
    Point the policy at a roots file holding the given text.

    Parameters:
      monkeypatch: Redirects the module-level file location.
      path: Where to write the file.
      body: File contents.
    """
    path.write_text(body, encoding="utf-8")
    monkeypatch.setattr(paths, "ROOTS_FILE", path)


def test_file_supplies_roots_when_env_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The config file is the source of truth by default."""
    monkeypatch.delenv(ALLOWED_ROOTS_VAR, raising=False)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    _write_roots_file(monkeypatch, tmp_path / "roots", f"{allowed}\n")

    current = paths.policy()

    assert current.roots == (allowed.resolve(),)
    assert current.source == str(tmp_path / "roots")


def test_env_overrides_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A locked-down install cannot be widened by editing a file."""
    from_file = tmp_path / "from_file"
    from_env = tmp_path / "from_env"
    from_file.mkdir()
    from_env.mkdir()

    _write_roots_file(monkeypatch, tmp_path / "roots", f"{from_file}\n")
    _set_roots(monkeypatch, from_env)

    assert paths.policy().roots == (from_env.resolve(),)


def test_comments_and_blanks_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A file of examples leaves the policy at its default."""
    monkeypatch.delenv(ALLOWED_ROOTS_VAR, raising=False)
    _write_roots_file(monkeypatch, tmp_path / "roots", "# ~/Downloads\n\n#~/Documents\n")

    current = paths.policy()

    assert current.roots == (Path.home().resolve(),)
    assert current.source == "default (home directory)"


def test_tilde_in_the_file_is_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Paths are written the way a user would type them."""
    monkeypatch.delenv(ALLOWED_ROOTS_VAR, raising=False)
    _write_roots_file(monkeypatch, tmp_path / "roots", "~\n")

    assert paths.policy().roots == (Path.home().resolve(),)
