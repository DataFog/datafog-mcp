"""Tests for the datafog-mcp command line."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from datafog_mcp import __main__ as cli
from datafog_mcp import paths
from datafog_mcp.paths import ALLOWED_ROOTS_VAR


def _run(monkeypatch: pytest.MonkeyPatch, *argv: str) -> None:
    """
    Invoke the console entry point with the given arguments.

    Parameters:
      monkeypatch: Replaces sys.argv for the duration of the call.
      argv: Arguments following the program name.
    """
    monkeypatch.setattr("sys.argv", ["datafog-mcp", *argv])
    cli.main()


def _use_roots_file(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    body: str | None = None,
) -> None:
    """
    Point both namespaces at a roots file and clear the override.

    ROOTS_FILE is read through paths for the policy lookup and through
    __main__ for display, so the two have to move together.

    Parameters:
      monkeypatch: Redirects the module-level constants.
      path: Where the roots file should live.
      body: Contents to write, or None to leave the file absent.
    """
    if body is not None:
        path.write_text(body, encoding="utf-8")

    monkeypatch.delenv(ALLOWED_ROOTS_VAR, raising=False)
    monkeypatch.setattr(paths, "ROOTS_FILE", path)
    monkeypatch.setattr(cli, "ROOTS_FILE", path)


def _capture_editor(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """
    Record editor invocations instead of spawning one.

    Parameters:
      monkeypatch: Replaces subprocess.run in the CLI module.
    Returns:
      A list that receives each command the CLI would have run.
    """
    calls: list[list[str]] = []

    def _fake_run(command: list[str], **kwargs: Any) -> None:
        """
        Record a command without executing it.

        Parameters:
          command: The argv the CLI passed.
          kwargs: Ignored subprocess options.
        """
        calls.append(command)

    monkeypatch.setattr(cli.subprocess, "run", _fake_run)
    return calls


def test_roots_reports_its_roots_and_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The configured roots, the file they came from, and the denials."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    roots = tmp_path / "allowed_roots"
    _use_roots_file(monkeypatch, roots, f"{allowed}\n")

    _run(monkeypatch, "roots")
    out = capsys.readouterr().out

    assert str(allowed) in out
    assert str(roots) in out
    assert ".ssh" in out


def test_roots_says_when_the_file_is_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unconfigured install is told how to configure itself."""
    _use_roots_file(monkeypatch, tmp_path / "absent")

    _run(monkeypatch, "roots")
    out = capsys.readouterr().out

    assert "not created yet" in out
    assert str(Path.home()) in out


def test_roots_warns_that_the_variable_wins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Editing the file is pointless while the override is set."""
    roots = tmp_path / "allowed_roots"
    _use_roots_file(monkeypatch, roots, f"{tmp_path}\n")
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, str(tmp_path))

    _run(monkeypatch, "roots")
    out = capsys.readouterr().out

    assert "edits have no effect" in out


def test_edit_creates_the_file_from_the_template(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A first edit writes the template, with examples commented out."""
    roots = tmp_path / "config" / "allowed_roots"
    _use_roots_file(monkeypatch, roots)
    calls = _capture_editor(monkeypatch)

    _run(monkeypatch, "roots", "--edit")

    assert roots.is_file()
    assert "# ~/Downloads" in roots.read_text(encoding="utf-8")
    assert calls[0][-1] == str(roots)


def test_edit_leaves_an_existing_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Opening the editor never overwrites what is already configured."""
    roots = tmp_path / "allowed_roots"
    _use_roots_file(monkeypatch, roots, "/srv/data\n")
    _capture_editor(monkeypatch)

    _run(monkeypatch, "roots", "--edit")

    assert roots.read_text(encoding="utf-8") == "/srv/data\n"


def test_edit_prefers_visual_over_editor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """VISUAL wins, per the usual convention."""
    _use_roots_file(monkeypatch, tmp_path / "allowed_roots", "")
    calls = _capture_editor(monkeypatch)
    monkeypatch.setenv("EDITOR", "an-editor")
    monkeypatch.setenv("VISUAL", "a-visual-editor")

    _run(monkeypatch, "roots", "--edit")

    assert calls[0][0] == "a-visual-editor"


def test_edit_falls_back_to_nano(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With neither variable set the CLI still opens something."""
    _use_roots_file(monkeypatch, tmp_path / "allowed_roots", "")
    calls = _capture_editor(monkeypatch)
    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.delenv("VISUAL", raising=False)

    _run(monkeypatch, "roots", "--edit")

    assert calls[0][0] == "nano"


@pytest.mark.parametrize("argv", [(), ("serve",)])
def test_serving_is_the_default(argv: tuple[str, ...], monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Bare invocation and serve both start the server.

    MCP registrations invoke the bare form, so this is the path a
    client depends on.
    """
    from datafog_mcp import server

    served: list[bool] = []
    monkeypatch.setattr(server, "run_server", lambda: served.append(True))

    _run(monkeypatch, *argv)

    assert served == [True]


def test_version_exits_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    """--version reports and stops rather than serving."""
    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, "--version")

    assert excinfo.value.code == 0


def test_edit_splits_editor_arguments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    An editor with flags is run as a command, not a program name.

    EDITOR="code --wait" is the common case that broke.
    """
    _use_roots_file(monkeypatch, tmp_path / "allowed_roots", "")
    calls = _capture_editor(monkeypatch)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv("EDITOR", "code --wait")

    _run(monkeypatch, "roots", "--edit")

    assert calls[0] == ["code", "--wait", str(tmp_path / "allowed_roots")]


def test_edit_honors_shell_quoting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A quoted path with a space survives as one argument."""
    roots = tmp_path / "allowed_roots"
    _use_roots_file(monkeypatch, roots, "")
    calls = _capture_editor(monkeypatch)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv("EDITOR", '"/Applications/My Editor" -w')

    _run(monkeypatch, "roots", "--edit")

    assert calls[0] == ["/Applications/My Editor", "-w", str(roots)]


def test_edit_reports_a_missing_editor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A nonexistent editor is one clear line, not a traceback."""
    _use_roots_file(monkeypatch, tmp_path / "allowed_roots", "")
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv("EDITOR", "no-such-editor-xyz")

    with pytest.raises(SystemExit, match="editor not found"):
        _run(monkeypatch, "roots", "--edit")
