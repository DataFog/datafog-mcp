"""Copy destinations are an owner policy, never an agent-selected allowed root."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import paths, policy
from datafog_mcp.paths import ALLOWED_ROOTS_VAR
from datafog_mcp.server import mcp

TOOLS = ["datafog_redact", "datafog_mask", "datafog_remove"]


def call(tool: str, source: Path, output: Path | None = None) -> dict[str, object]:
    async def run() -> dict[str, object]:
        arguments: dict[str, Any] = {"path": str(source), "entity_types": ["EMAIL"]}
        if output is not None:
            arguments["output_path"] = str(output)
        async with Client(mcp) as client:
            result = await client.call_tool(tool, arguments)
            return result.structured_content or {}

    return asyncio.run(run())


def configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str) -> None:
    location = tmp_path / "configuration" / "policy.toml"
    location.parent.mkdir(exist_ok=True)
    location.write_text(body, encoding="utf-8")
    monkeypatch.setattr(policy, "POLICY_FILE", location)
    monkeypatch.setattr(paths, "ROOTS_FILE", location.with_name("allowed_roots"))


def directory_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, directory: Path) -> None:
    configure(
        monkeypatch, tmp_path, f'version = 1\n[output]\ndirectory = "{directory.as_posix()}"\n'
    )


@pytest.mark.parametrize("tool", TOOLS)
def test_configured_directory_gets_default_copy(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("contact: person@example.com", encoding="utf-8")
    if os.name == "posix":
        source.chmod(0o600)
    output = tmp_path / "copies"
    output.mkdir()
    directory_policy(monkeypatch, tmp_path, output)

    result = call(tool, source)
    written = Path(str(result["output_path"]))
    assert written.parent == output.resolve()
    if os.name == "posix":
        assert written.stat().st_mode & 0o777 == 0o600
    assert "person@example.com" not in written.read_text(encoding="utf-8")
    assert "person@example.com" not in str(result)
    assert source.read_text(encoding="utf-8") == "contact: person@example.com"
    assert list(tmp_path.glob("input_*.txt")) == []


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("destination", ["sibling", "other-root", "nested"])
def test_explicit_destination_cannot_escape_configured_directory(
    tool: str, destination: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("person@example.com", encoding="utf-8")
    copies = tmp_path / "copies"
    copies.mkdir()
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    nested = copies / "nested"
    nested.mkdir()
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, os.pathsep.join([str(tmp_path), str(elsewhere)]))
    directory_policy(monkeypatch, tmp_path, copies)
    parent = {"sibling": tmp_path, "other-root": elsewhere, "nested": nested}[destination]
    target = parent / "out.txt"

    with pytest.raises(ToolError, match="configured output directory"):
        call(tool, source, target)
    assert not target.exists()


def test_explicit_name_in_configured_directory_and_no_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("person@example.com", encoding="utf-8")
    copies = tmp_path / "copies"
    copies.mkdir()
    directory_policy(monkeypatch, tmp_path, copies)
    target = copies / "custom.txt"
    call("datafog_redact", source, target)
    assert target.read_text(encoding="utf-8") == "[EMAIL]"
    with pytest.raises(ToolError, match="already exists"):
        call("datafog_mask", source, target)
    assert target.read_text(encoding="utf-8") == "[EMAIL]"


@pytest.mark.parametrize("kind", ["outside-roots", "empty-roots", "credential", "configuration"])
def test_output_configuration_never_grants_access(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    source = inputs / "input.txt"
    source.write_text("person@example.com", encoding="utf-8")
    copies = tmp_path / {"credential": ".ssh", "configuration": "configuration"}.get(kind, "copies")
    copies.mkdir()
    directory_policy(monkeypatch, tmp_path, copies)
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, str(inputs) if kind == "outside-roots" else str(tmp_path))
    if kind == "empty-roots":
        monkeypatch.setenv(ALLOWED_ROOTS_VAR, "")

    with pytest.raises(ToolError):
        call("datafog_redact", source)
    assert not (copies / "input_redacted.txt").exists()


@pytest.mark.parametrize(
    "body",
    [
        "",
        "version = 2",
        "version = true",
        'version = 1\nunknown = "secret"',
        'version = 1\noutput = "bad"',
        'version = 1\n[output]\ndirectroy = "secret"',
        'version = 1\n[output]\ndirectory = ""',
        'version = 1\n[output]\ndirectory = "relative"',
        "version = 1\n[output]\ndirectory = 42",
        "not valid TOML secret@example.com",
    ],
)
def test_unusable_policy_refuses_writes_without_falling_back(
    body: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("person@example.com", encoding="utf-8")
    configure(monkeypatch, tmp_path, body)
    with pytest.raises(ToolError) as excinfo:
        call("datafog_redact", source)
    assert "secret@example.com" not in str(excinfo.value)
    assert not (tmp_path / "input_redacted.txt").exists()


def test_policy_reloaded_and_missing_output_is_not_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("person@example.com", encoding="utf-8")
    configure(monkeypatch, tmp_path, "version = 1")
    result = call("datafog_redact", source)
    assert Path(str(result["output_path"])).parent == tmp_path.resolve()
    copies = tmp_path / "missing"
    directory_policy(monkeypatch, tmp_path, copies)
    with pytest.raises(ToolError, match="cannot be resolved"):
        call("datafog_mask", source)
    assert not copies.exists()
    assert not (tmp_path / "input_masked.txt").exists()


@pytest.mark.parametrize("tool", TOOLS)
def test_insufficient_space_is_actionable_through_mcp(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("contact person@example.com", encoding="utf-8")
    copies = tmp_path / "copies"
    copies.mkdir()
    directory_policy(monkeypatch, tmp_path, copies)
    monkeypatch.setattr("datafog_mcp.reader.shutil.disk_usage", lambda _: SimpleNamespace(free=0))
    with pytest.raises(ToolError, match="not enough free space") as excinfo:
        call(tool, source)
    assert "person@example.com" not in str(excinfo.value)
    assert list(copies.iterdir()) == []
    assert source.read_text(encoding="utf-8") == "contact person@example.com"


@pytest.mark.parametrize("kind", ["directory", "dangling-link", "invalid-utf8", "file-target"])
def test_unusable_policy_paths_fail_closed(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("person@example.com", encoding="utf-8")
    location = tmp_path / "policy.toml"
    monkeypatch.setattr(policy, "POLICY_FILE", location)
    if kind == "directory":
        location.mkdir()
    elif kind == "dangling-link":
        location.symlink_to(tmp_path / "absent")
    elif kind == "invalid-utf8":
        location.write_bytes(b"\xff")
    else:
        directory_policy(monkeypatch, tmp_path, source)
    with pytest.raises(ToolError):
        call("datafog_redact", source)
    assert not (tmp_path / "input_redacted.txt").exists()


def test_symlink_cannot_redirect_output_to_another_allowed_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("person@example.com", encoding="utf-8")
    copies = tmp_path / "copies"
    elsewhere = tmp_path / "elsewhere"
    copies.mkdir()
    elsewhere.mkdir()
    link = copies / "escape"
    link.symlink_to(elsewhere, target_is_directory=True)
    directory_policy(monkeypatch, tmp_path, copies)
    with pytest.raises(ToolError, match="configured output directory"):
        call("datafog_redact", source, link / "out.txt")
    assert not (elsewhere / "out.txt").exists()
