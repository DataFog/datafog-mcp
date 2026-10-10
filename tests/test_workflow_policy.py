"""Real MCP calls enforce root/scope separation and consistent private allowlists."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import paths, policy, server
from datafog_mcp.paths import ALLOWED_ROOTS_VAR

TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]
APPROVED = "public-support@example.com"
PRIVATE = "private-person@example.com"


def configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    location = tmp_path / "policy.toml"
    location.write_text("version = 1\n" + body, encoding="utf-8")
    monkeypatch.setattr(policy, "POLICY_FILE", location)
    return location


def call(tool: str, source: Path | None = None, **options: Any) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        arguments = dict(options)
        if source is not None:
            arguments["path"] = str(source)
        async with Client(server.mcp) as client:
            result = await client.call_tool(tool, arguments)
            assert APPROVED not in str(result.content)
            assert PRIVATE not in str(result.content)
            return result.structured_content or {}

    return asyncio.run(run())


@pytest.mark.parametrize("tool", TOOLS)
def test_exact_allowlist_applies_to_scans_and_all_writes(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = f"{APPROVED}\n{PRIVATE}\nPUBLIC-SUPPORT@example.com\nother-public-support@example.com"
    source = tmp_path / "input.txt"
    source.write_text(text, encoding="utf-8")
    configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL = ["{APPROVED}"]')
    result = call(tool, source, entity_types=["EMAIL"])
    assert result["counts"] == {"EMAIL": 3}
    assert result["entity_count"] == 3
    if tool == "datafog_scan":
        assert result["findings"][0]["start"] == text.index(PRIVATE)
    else:
        output = Path(result["output_path"]).read_text(encoding="utf-8")
        assert output.startswith(APPROVED + "\n")
        assert PRIVATE not in output
        assert "PUBLIC-SUPPORT@example.com" not in output
        assert "other-public-support@example.com" not in output
    assert source.read_text(encoding="utf-8") == text


def test_allowlists_are_entity_specific(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "input.txt"
    source.write_text("NPI: 1234567893", encoding="utf-8")
    configure(tmp_path, monkeypatch, '[allow.exact]\nNPI = ["1234567893"]')
    result = call("datafog_scan", source, entity_types=["NPI", "PHONE"])
    assert result["counts"] == {"PHONE": 1}


def test_scope_guides_checks_but_does_not_disable_explicit_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "exports"
    folder.mkdir()
    configure(
        tmp_path, monkeypatch, f'[scope]\nfolders = ["{folder.as_posix()}"]\nextensions = [".CSV"]'
    )
    for name, expected in [
        ("exports/input.CSV", True),
        ("exports/input.txt", False),
        ("elsewhere.csv", False),
    ]:
        source = tmp_path / name
        source.write_text(PRIVATE, encoding="utf-8")
        result = call("datafog_scan", source, entity_types=["EMAIL"], has_header=False)
        assert result["entity_count"] == 1
        assert result["policy"]["scan_before_read"] is expected
        assert call("datafog_policy", source)["scan_before_read"] is expected


@pytest.mark.parametrize("tool", [*TOOLS, "datafog_policy"])
@pytest.mark.parametrize("kind", ["outside", "symlink", "empty", "credential"])
def test_invalid_scope_never_expands_roots_or_falls_back(
    tool: str, kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    source = allowed / "input.txt"
    source.write_text(PRIVATE, encoding="utf-8")
    folder = allowed
    if kind == "outside":
        folder = outside
    elif kind == "symlink":
        folder = allowed / "link"
        folder.symlink_to(outside, target_is_directory=True)
    elif kind == "credential":
        folder = allowed / ".SSH"
        folder.mkdir()
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, "" if kind == "empty" else str(allowed))
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{folder.as_posix()}"]')
    with pytest.raises(ToolError, match="scanning scope folder"):
        call(tool, source)
    assert sorted(path.name for path in allowed.glob("input*")) == ["input.txt"]


def test_scope_revalidated_after_roots_narrowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exports = tmp_path / "exports"
    other = tmp_path / "other"
    exports.mkdir()
    other.mkdir()
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{exports.as_posix()}"]')
    assert call("datafog_policy", exports / "input.txt")["scan_before_read"] is True
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, str(other))
    with pytest.raises(ToolError, match="outside allowed roots"):
        call("datafog_policy")


def test_scope_revalidated_after_symlink_retargeted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    link = allowed / "exports"
    link.symlink_to(allowed, target_is_directory=True)
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, str(allowed))
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{link.as_posix()}"]')
    call("datafog_policy")
    link.unlink()
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ToolError, match="outside allowed roots"):
        call("datafog_policy")


@pytest.mark.parametrize("action", ["ask", "transform", "stop"])
def test_workflow_actions_are_advisory_without_implicit_writes(
    action: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text(PRIVATE, encoding="utf-8")
    configure(
        tmp_path, monkeypatch, f'[workflow]\non_findings = "{action}"\ntransform_strategy = "mask"'
    )
    result = call("datafog_scan", source, entity_types=["EMAIL"])
    assert result["policy"]["action"] == action
    assert result["policy"]["advisory"] is True
    if action == "transform":
        assert result["policy"]["transform_strategy"] == "mask"
    assert not list(tmp_path.glob("input_*.txt"))
    # An explicit write remains the requested strategy; workflow settings guide
    # the agent rather than override an authorized tool call.
    output = call("datafog_redact", source, entity_types=["EMAIL"])
    assert Path(output["output_path"]).read_text(encoding="utf-8") == "[EMAIL]"


def test_allowlisted_only_scan_proceeds_without_exposing_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "input.txt"
    source.write_text(APPROVED, encoding="utf-8")
    configure(
        tmp_path,
        monkeypatch,
        f'[workflow]\non_findings = "stop"\n[allow.exact]\nEMAIL = ["{APPROVED}"]',
    )
    result = call("datafog_scan", source, entity_types=["EMAIL"])
    assert result["entity_count"] == 0
    assert result["policy"]["action"] == "proceed"
    discovery = call("datafog_policy")
    assert discovery["allowlist_counts"] == {"EMAIL": 1}
    assert APPROVED not in json.dumps(discovery)


@pytest.mark.parametrize(
    "body",
    [
        '[allow.exact]\nEMAIL = "private-person@example.com"',
        '[allow.exact]\nUNKNOWN = ["private-person@example.com"]',
        '[scope]\nextensions = ["csv"]',
        '[scope]\nfolders = ["relative"]',
        '[workflow]\non_findings = "private-person@example.com"',
        '[workflow]\ntransform_strategy = "custom"',
        '[scope]\nfolder = ["secret"]',
    ],
)
def test_invalid_policy_refuses_scan_without_echoing_values(
    body: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    source = tmp_path / "input.txt"
    source.write_text(PRIVATE, encoding="utf-8")
    configure(tmp_path, monkeypatch, body)
    with pytest.raises(ToolError) as excinfo:
        call("datafog_scan", source)
    captured = capfd.readouterr()
    assert PRIVATE not in str(excinfo.value) + captured.out + captured.err + caplog.text


@pytest.mark.parametrize("suffix", ["txt", "csv", "tsv"])
def test_request_uses_one_snapshot_and_next_request_reloads(
    suffix: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / f"input.{suffix}"
    header = "email\n" if suffix != "txt" else ""
    source.write_text(header + f"{APPROVED}\n{PRIVATE}", encoding="utf-8")
    location = configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL = ["{APPROVED}"]')
    actual_scan = server.scan

    def scan(text: str, config: Any = None) -> Any:
        location.write_text("broken policy", encoding="utf-8")
        return actual_scan(text, config)

    monkeypatch.setattr(server, "scan", scan)
    result = call("datafog_redact", source, entity_types=["EMAIL"])
    assert result["entity_count"] == 1
    replacement = "[EMAIL]" if suffix == "txt" else '"[EMAIL]"'
    assert (
        Path(result["output_path"]).read_text(encoding="utf-8")
        == header + APPROVED + "\n" + replacement
    )
    with pytest.raises(ToolError, match="valid UTF-8 TOML"):
        call("datafog_scan", source)


def test_scope_does_not_override_request_path_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, str(tmp_path / "allowed"))
    (tmp_path / "allowed").mkdir()
    configure(tmp_path, monkeypatch, "")
    with pytest.raises(ToolError, match="outside the allowed roots"):
        call("datafog_policy", tmp_path / "outside.txt")


def test_scope_revalidated_after_roots_file_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "exports"
    other = tmp_path / "other"
    folder.mkdir()
    other.mkdir()
    roots = tmp_path / "allowed_roots"
    roots.write_text(str(tmp_path), encoding="utf-8")
    monkeypatch.delenv(ALLOWED_ROOTS_VAR)
    monkeypatch.setattr(paths, "ROOTS_FILE", roots)
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{folder.as_posix()}"]')
    call("datafog_policy")
    roots.write_text(str(other), encoding="utf-8")
    with pytest.raises(ToolError, match="outside allowed roots"):
        call("datafog_policy")


def test_discovery_refuses_credential_path_inside_valid_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{tmp_path.as_posix()}"]')
    with pytest.raises(ToolError, match="credential directory"):
        call("datafog_policy", tmp_path / ".ssh" / "private.txt")


def test_missing_policy_defaults_to_ask_and_unrestricted_scope(tmp_path: Path) -> None:
    source = tmp_path / "input.txt"
    source.write_text(PRIVATE, encoding="utf-8")
    result = call("datafog_scan", source, entity_types=["EMAIL"])
    assert result["policy"] == {"advisory": True, "scan_before_read": True, "action": "ask"}


def test_owner_cli_prints_counts_without_allowlist_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from datafog_mcp import __main__ as cli

    configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL = ["{APPROVED}"]')
    monkeypatch.setattr("sys.argv", ["datafog-mcp", "policy"])
    cli.main()
    output = capsys.readouterr().out
    assert "EMAIL=1" in output
    assert APPROVED not in output


def test_loaded_snapshot_cannot_be_mutated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL = ["{APPROVED}"]')
    current = policy.load_output_policy()
    with pytest.raises(TypeError):
        current.allow_exact["EMAIL"] = frozenset()  # type: ignore[index]


@pytest.mark.parametrize("kind", ["file", "malformed-roots"])
def test_unusable_scope_configuration_never_falls_back(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "scope"
    if kind == "file":
        folder.write_text("not a directory", encoding="utf-8")
    elif kind == "malformed-roots":
        folder.mkdir()
        monkeypatch.setenv(ALLOWED_ROOTS_VAR, "relative-root")
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{folder.as_posix()}"]')
    with pytest.raises(ToolError):
        call("datafog_policy")


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("delimiter,suffix", [(",", "csv"), ("\t", "tsv")])
def test_table_allowlists_use_decoded_values_and_preserve_locations(
    tool: str, delimiter: str, suffix: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / f"input.{suffix}"
    text = (
        f'email{delimiter}NPI\r\n"{APPROVED}"{delimiter}1234567893\r\n'
        f'"{PRIVATE}"{delimiter}1234567893\r\n'
    )
    source.write_bytes(text.encode())
    configure(
        tmp_path,
        monkeypatch,
        f'[allow.exact]\nEMAIL = ["{APPROVED}"]\nNPI = ["1234567893"]',
    )
    result = call(tool, source, entity_types=["EMAIL", "NPI"])
    assert result["counts"] == {"EMAIL": 1}
    if tool == "datafog_scan":
        finding = result["findings"][0]
        assert finding["record"] == 2
        assert finding["column"] == 1
        assert text[finding["start"] : finding["end"]] == PRIVATE
        assert result["policy"]["action"] == "ask"
    else:
        output = Path(result["output_path"]).read_bytes().decode()
        assert output.startswith(f'email{delimiter}NPI\r\n"{APPROVED}"{delimiter}1234567893\r\n')
        assert PRIVATE not in output
        assert output.count("1234567893") == 2
        assert output.count("\r\n") == 3
    assert source.read_bytes().decode() == text


@pytest.mark.parametrize("suffix", ["txt", "csv", "tsv"])
def test_allowlists_apply_before_response_cutoff(
    suffix: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / f"input.{suffix}"
    header = "email\n" if suffix != "txt" else ""
    source.write_text(header + (APPROVED + "\n") * 701 + PRIVATE + "\n", encoding="utf-8")
    configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL = ["{APPROVED}"]')
    result = call("datafog_scan", source, entity_types=["EMAIL"])
    assert result["entity_count"] == 1
    assert result["findings_listed"] is True
    assert len(result["findings"]) == 1
    configure(tmp_path, monkeypatch, '[workflow]\non_findings = "stop"')
    result = call("datafog_scan", source, entity_types=["EMAIL"])
    assert result["entity_count"] == 702
    assert result["findings_listed"] is False
    assert result["findings"] == []
    assert result["policy"]["action"] == "stop"


@pytest.mark.parametrize("tool", [*TOOLS, "datafog_policy"])
def test_deleted_scope_folder_warns_without_blocking_explicit_operations(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "exports"
    folder.mkdir()
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{folder.as_posix()}"]')
    assert call("datafog_policy", folder / "future.txt")["scan_before_read"] is True
    folder.rmdir()
    source = tmp_path / "other.txt"
    source.write_text(PRIVATE, encoding="utf-8")
    result = (
        call(tool, source, entity_types=["EMAIL"])
        if tool != "datafog_policy"
        else call(tool, source)
    )
    assert result["warnings"]
    assert str(folder) not in json.dumps(result["warnings"])
    if tool == "datafog_policy":
        assert result["scope"]["folders"] == [str(folder)]
        assert result["scope"]["available_folders"] == []
        assert result["scope"]["missing_folders"] == [str(folder)]
        assert result["scan_before_read"] is False
    elif tool == "datafog_scan":
        assert result["entity_count"] == 1
        assert result["policy"]["scan_before_read"] is False
    else:
        assert result["entity_count"] == 1
        assert PRIVATE not in Path(result["output_path"]).read_text(encoding="utf-8")
    assert source.read_text(encoding="utf-8") == PRIVATE
    # Even discovery of a future path must not treat a missing restriction as
    # the deliberately empty list that means all allowed directories.
    assert call("datafog_policy", folder / "future.txt")["scan_before_read"] is False
    folder.mkdir()
    restored = call("datafog_policy", folder / "future.txt")
    assert restored["scan_before_read"] is True
    assert restored["scope"]["missing_folders"] == []
    assert "warnings" not in restored


def test_missing_folder_keeps_other_scope_folders_and_extension_restrictions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "missing"
    available = tmp_path / "available"
    available.mkdir()
    configure(
        tmp_path,
        monkeypatch,
        f'[scope]\nfolders = ["{missing}", "{available}"]\nextensions = [".txt"]',
    )
    for source, expected in [
        (available / "input.txt", True),
        (available / "input.csv", False),
        (tmp_path / "elsewhere.txt", False),
    ]:
        result = call("datafog_policy", source)
        assert result["scan_before_read"] is expected
        assert result["scope"]["available_folders"] == [str(available)]
        assert result["scope"]["missing_folders"] == [str(missing)]


@pytest.mark.parametrize("kind", ["outside", "credential", "symlink"])
def test_missing_scope_still_enforces_access_boundaries(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, str(allowed))
    folder = tmp_path / "outside" / "missing"
    if kind == "credential":
        folder = allowed / ".ssh" / "missing"
    elif kind == "symlink":
        link = allowed / "link"
        link.symlink_to(tmp_path / "outside", target_is_directory=True)
        folder = link / "missing"
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{folder}"]')
    with pytest.raises(ToolError, match="outside allowed roots|credential directory"):
        call("datafog_policy")


def test_scope_permission_error_is_not_reported_as_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "private"
    folder.mkdir()
    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{folder}"]')
    actual_resolve = Path.resolve

    def resolve(path: Path, strict: bool = False) -> Path:
        if path == folder:
            raise PermissionError("sensitive details")
        return actual_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve)
    with pytest.raises(ToolError, match="cannot be resolved"):
        call("datafog_policy")


def test_owner_cli_reports_missing_scope_without_claiming_unrestricted_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from datafog_mcp import __main__ as cli

    configure(tmp_path, monkeypatch, f'[scope]\nfolders = ["{tmp_path / "missing"}"]')
    monkeypatch.setattr("sys.argv", ["datafog-mcp", "policy"])
    cli.main()
    output = capsys.readouterr().out
    assert "missing; inactive" in output
    assert "Warning:" in output
    assert "all allowed directories" not in output
