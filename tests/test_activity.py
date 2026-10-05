"""Optional activity metadata stays private, bounded, and independent of tool outcomes."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import __main__ as cli
from datafog_mcp import activity, policy, server
from datafog_mcp.keys import generate_scope_key
from datafog_mcp.policy import ActivityPolicy, OutputPolicy, PseudonymScope

PRIVATE = "private-person@example.com"
DRAFT = f"DRAFT_SENTINEL Contact {PRIVATE}"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private activity file requires POSIX")


@pytest.fixture
def configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> OutputPolicy:
    directory = tmp_path / "private-activity"
    directory.mkdir(mode=0o700)
    path = directory / "activity.jsonl"
    config = tmp_path / "policy.toml"
    config.write_text(f"version=1\n[activity]\nenabled=true\npath={json.dumps(str(path))}\n")
    monkeypatch.setattr(policy, "POLICY_FILE", config)
    current = policy.load_output_policy()
    activity.initialize(current)
    return current


def call(tool: str = "datafog_check_text", **arguments: Any) -> Any:
    async def run() -> Any:
        async with Client(server.mcp) as client:
            return await client.call_tool(tool, arguments)

    return asyncio.run(run())


def rows(current: OutputPolicy) -> list[dict[str, Any]]:
    assert current.activity.path is not None
    return [json.loads(line) for line in current.activity.path.read_text().splitlines()]


def test_disabled_default_and_explicit_disabled_have_no_activity_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Disabled logging touched activity storage")

    monkeypatch.setattr(activity, "record", forbidden)
    assert "activity_log" not in call(text=DRAFT).structured_content
    config = tmp_path / "policy.toml"
    config.write_text(
        f"version=1\n[activity]\nenabled=false\npath={json.dumps(str(tmp_path / 'absent' / 'log'))}"
    )
    monkeypatch.setattr(policy, "POLICY_FILE", config)
    assert "activity_log" not in call(text=DRAFT).structured_content
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("tool", sorted(activity.OPERATIONS))
def test_all_tools_record_only_explicit_metadata(
    tool: str, configured: OutputPolicy, tmp_path: Path
) -> None:
    source = tmp_path / "sensitive-filename.txt"
    source.write_text(DRAFT)
    args: dict[str, Any] = {"path": str(source)}
    if tool == "datafog_check_text":
        args = {"text": DRAFT}
    elif tool == "datafog_pseudonymize":
        key = tmp_path / "key"
        generate_scope_key(PseudonymScope("secret-key-reference", "file", key))
        with policy.POLICY_FILE.open("a") as handle:
            handle.write(
                '[pseudonymization.scopes.customers]\nkey_ref="secret-key-reference"\nbackend="file"\n'
                + f"key_file={json.dumps(str(key))}\n"
            )
        args["scope"] = "customers"
    result = call(tool, **args)
    assert result.structured_content["activity_log"] == {"status": "recorded"}
    entries = rows(configured)
    assert len(entries) == 1
    entry = entries[0]
    assert set(entry) == {"schema", "time", "operation", "outcome", "counts"}
    assert entry["operation"] == tool and entry["outcome"] == "success"
    assert entry["counts"] == ({} if tool == "datafog_policy" else {"EMAIL": 1})
    from datetime import datetime

    offset = datetime.fromisoformat(entry["time"]).utcoffset()
    assert offset is not None and offset.total_seconds() == 0
    payload = json.dumps(entry)
    for value in (
        PRIVATE,
        "DRAFT_SENTINEL",
        "sensitive-filename",
        str(tmp_path),
        "customers",
        "secret-key-reference",
    ):
        assert value not in payload
    assert source.read_text() == DRAFT


def test_validation_and_engine_errors_record_no_exception_or_arguments(
    configured: OutputPolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ToolError):
        call(text=DRAFT, entity_types=[DRAFT])

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(DRAFT)

    monkeypatch.setattr(server, "scan", broken)
    with pytest.raises(ToolError, match="details are withheld"):
        call(text=DRAFT)
    entries = rows(configured)
    assert [entry["outcome"] for entry in entries] == ["error", "error"]
    assert all(entry["counts"] == {} for entry in entries)
    assert PRIVATE not in json.dumps(entries) and "RuntimeError" not in json.dumps(entries)


def test_unavailable_log_preserves_successful_copy_and_displays_warning(
    configured: OutputPolicy, tmp_path: Path
) -> None:
    assert configured.activity.path is not None
    configured.activity.path.unlink()
    source = tmp_path / "input.txt"
    source.write_text(DRAFT)
    data = call("datafog_redact", path=str(source)).structured_content
    assert data["activity_log"] == {"status": "unavailable", "warning": activity.WARNING}
    assert PRIVATE not in Path(data["output_path"]).read_text()
    assert source.read_text() == DRAFT
    assert not configured.activity.path.exists()


def test_unavailable_log_preserves_original_error_and_warning(
    configured: OutputPolicy, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise OSError(DRAFT)

    monkeypatch.setattr(activity.os, "write", broken)
    with pytest.raises(ToolError) as caught:
        call(text=DRAFT, entity_types=[])
    assert "nonempty" in str(caught.value) and activity.WARNING in str(caught.value)
    assert PRIVATE not in str(caught.value) + caplog.text
    assert rows(configured) == []


@pytest.mark.parametrize(
    "kind",
    ["file-mode", "directory-mode", "symlink", "parent-symlink", "hardlink", "fifo", "directory"],
)
def test_unsafe_storage_never_changes_existing_targets(
    kind: str, configured: OutputPolicy, tmp_path: Path
) -> None:
    path = configured.activity.path
    assert path is not None
    target = tmp_path / "target"
    target.write_text(DRAFT)
    if kind == "file-mode":
        path.chmod(0o644)
    elif kind == "directory-mode":
        path.parent.chmod(0o755)
    elif kind == "parent-symlink":
        directory = path.parent
        renamed = directory.with_name("actual-storage")
        directory.rename(renamed)
        directory.symlink_to(renamed, target_is_directory=True)
    else:
        path.unlink()
        if kind == "symlink":
            path.symlink_to(target)
        elif kind == "hardlink":
            os.link(target, path)
        elif kind == "fifo":
            os.mkfifo(path, 0o600)
        else:
            path.mkdir()
    assert not activity.record(configured, "datafog_scan", "success", {"EMAIL": 1})
    assert target.read_text() == DRAFT
    with pytest.raises(activity.ActivityStorageError):
        activity.verify(configured)


def test_capacity_cap_stops_appending_without_deleting_records(
    configured: OutputPolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert activity.record(configured, "datafog_scan", "success", {"EMAIL": 1})
    path = configured.activity.path
    assert path is not None
    original = path.read_bytes()
    monkeypatch.setattr(activity, "MAX_LOG_BYTES", len(original))
    assert not activity.record(configured, "datafog_check_text", "success", {"EMAIL": 1})
    assert path.read_bytes() == original
    assert call(text=DRAFT).structured_content["activity_log"]["warning"] == activity.WARNING


def test_partial_append_rolls_back_to_previous_complete_records(
    configured: OutputPolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert activity.record(configured, "datafog_scan", "success", {})
    path = configured.activity.path
    assert path is not None
    original = path.read_bytes()
    real_write = os.write
    monkeypatch.setattr(
        activity.os, "write", lambda descriptor, data: real_write(descriptor, data[:20])
    )
    assert not activity.record(configured, "datafog_scan", "success", {})
    assert path.read_bytes() == original


def test_other_process_lock_never_blocks_or_corrupts_log(configured: OutputPolicy) -> None:
    import fcntl

    assert configured.activity.path is not None
    with configured.activity.path.open("rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not activity.record(configured, "datafog_scan", "success", {})
    assert activity.record(configured, "datafog_scan", "success", {})
    assert len(rows(configured)) == 1


@pytest.mark.parametrize(
    "tool", ["datafog_policy", "datafog_scan", "datafog_redact", "datafog_pseudonymize"]
)
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink"])
def test_activity_assets_and_aliases_are_refused_as_data(
    tool: str, alias: str, configured: OutputPolicy, tmp_path: Path
) -> None:
    path = configured.activity.path
    assert path is not None
    if alias != "direct":
        candidate = tmp_path / "alias.txt"
        if alias == "symlink":
            candidate.symlink_to(path)
        else:
            os.link(path, candidate)
        path = candidate
    args = {"path": str(path)}
    if tool == "datafog_pseudonymize":
        # Missing scope is another refusal; use a configured key so private-file check is exercised.
        key = tmp_path / "key"
        generate_scope_key(PseudonymScope("scope-key", "file", key))
        with policy.POLICY_FILE.open("a") as handle:
            handle.write(
                '[pseudonymization.scopes.scope]\nkey_ref="scope-key"\nbackend="file"\n'
                + f"key_file={json.dumps(str(key))}\n"
            )
        args["scope"] = "scope"
    with pytest.raises(ToolError, match="activity storage"):
        call(tool, **args)


def test_activity_directory_refused_as_copy_destination(
    configured: OutputPolicy, tmp_path: Path
) -> None:
    assert configured.activity.path is not None
    with policy.POLICY_FILE.open("a") as handle:
        handle.write(f"[output]\ndirectory={json.dumps(str(configured.activity.path.parent))}\n")
    source = tmp_path / "input.txt"
    source.write_text(PRIVATE)
    with pytest.raises(ToolError, match="activity storage"):
        call("datafog_redact", path=str(source))
    assert not (configured.activity.path.parent / "input_redacted.txt").exists()


def test_log_cannot_append_to_key_or_configuration_directory(
    configured: OutputPolicy, tmp_path: Path
) -> None:
    # Paths outside the dedicated private directory cannot be repurposed as the log.
    reused = replace(configured, activity=ActivityPolicy(True, policy.POLICY_FILE))
    assert not activity.record(reused, "datafog_scan", "success", {})
    assert policy.POLICY_FILE.read_text().startswith("version=1")


def test_strict_activity_settings_never_echo_private_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for body in (
        'enabled="PRIVATE_SENTINEL"',
        "enabled=true",
        'enabled=true\npath="relative"',
        'path="/tmp/../PRIVATE_SENTINEL"',
        'extra="PRIVATE_SENTINEL"',
    ):
        config = tmp_path / "policy.toml"
        config.write_text("version=1\n[activity]\n" + body)
        monkeypatch.setattr(policy, "POLICY_FILE", config)
        with pytest.raises(policy.OutputPolicyError) as caught:
            policy.load_output_policy()
        assert "PRIVATE_SENTINEL" not in str(caught.value)


def test_cli_init_and_status_are_explicit_and_do_not_replace_records(
    configured: OutputPolicy, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = configured.activity.path
    assert path is not None
    path.unlink()
    monkeypatch.setattr("sys.argv", ["datafog-mcp", "activity", "init"])
    cli.main()
    assert "initialized" in capsys.readouterr().out
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert activity.record(configured, "datafog_check_text", "success", {"EMAIL": 1})
    original = path.read_bytes()
    with pytest.raises(SystemExit, match="refusing replacement"):
        cli.main()
    monkeypatch.setattr("sys.argv", ["datafog-mcp", "activity", "status"])
    cli.main()
    assert "verified" in capsys.readouterr().out
    assert path.read_bytes() == original


def test_discovery_reports_configuration_without_log_path(configured: OutputPolicy) -> None:
    data = call("datafog_policy").structured_content
    assert data["activity_logging"] == {
        "enabled": True,
        "storage": "private_posix_file",
        "max_bytes": activity.MAX_LOG_BYTES,
        "verified": False,
    }
    assert str(configured.activity.path) not in json.dumps(data)


def test_wrong_owner_refuses_append(
    configured: OutputPolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert configured.activity.path is not None
    original = configured.activity.path.read_bytes()
    uid = os.getuid()
    monkeypatch.setattr(activity.os, "getuid", lambda: uid + 1)
    assert not activity.record(configured, "datafog_scan", "success", {})
    assert configured.activity.path.read_bytes() == original


def test_one_policy_snapshot_survives_mid_operation_edit(
    configured: OutputPolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_scan = server.scan

    def edited(text: str) -> Any:
        policy.POLICY_FILE.write_text("version=1\n[activity]\nenabled=false\n")
        return real_scan(text)

    monkeypatch.setattr(server, "scan", edited)
    assert call(text=DRAFT).structured_content["activity_log"] == {"status": "recorded"}
    assert len(rows(configured)) == 1
    assert "activity_log" not in call(text=DRAFT).structured_content
    assert len(rows(configured)) == 1
    assert activity.CURRENT_POLICY.get() is None


def test_record_whitelist_discards_untrusted_metadata(configured: OutputPolicy) -> None:
    assert activity.record(
        configured,
        "datafog_scan",
        "success",
        {PRIVATE: 1, "EMAIL": PRIVATE, "SSN": True, "PHONE": -1, "DATE": 2},
    )
    assert rows(configured)[0]["counts"] == {"DATE": 2}
    assert PRIVATE not in json.dumps(rows(configured))
    assert not activity.record(configured, PRIVATE, "success", {})
    assert not activity.record(configured, "datafog_scan", PRIVATE, {})
    assert len(rows(configured)) == 1


def test_disabled_logging_still_protects_retained_log(configured: OutputPolicy) -> None:
    assert configured.activity.path is not None
    policy.POLICY_FILE.write_text(
        "version=1\n[activity]\nenabled=false\n"
        + f"path={json.dumps(str(configured.activity.path))}\n"
    )
    with pytest.raises(ToolError, match="activity storage"):
        call("datafog_scan", path=str(configured.activity.path))
    assert rows(configured) == []


def test_stdio_activity_records_and_warnings_are_visible(
    configured: OutputPolicy, tmp_path: Path
) -> None:
    import sys

    from fastmcp.client.transports import StdioTransport

    log_path = configured.activity.path
    assert log_path is not None
    stderr = tmp_path / "stderr.log"
    code = (
        "from pathlib import Path; from datafog_mcp import policy; "
        f"policy.POLICY_FILE=Path({str(policy.POLICY_FILE)!r}); "
        "from datafog_mcp.server import run_server; run_server()"
    )

    async def run() -> None:
        transport = StdioTransport(sys.executable, ["-c", code], log_file=stderr)
        async with Client(transport) as client:
            result = await client.call_tool("datafog_check_text", {"text": DRAFT})
            data = result.structured_content
            assert data is not None
            assert data["activity_log"] == {"status": "recorded"}
            assert "recorded" in str(result.content)
            log_path.unlink()
            result = await client.call_tool("datafog_check_text", {"text": DRAFT})
            data = result.structured_content
            assert data is not None
            assert data["counts"] == {"EMAIL": 1}
            from mcp.types import TextContent

            assert any(
                activity.WARNING in block.text
                for block in result.content
                if isinstance(block, TextContent)
            )
            with pytest.raises(ToolError) as caught:
                await client.call_tool("datafog_check_text", {"text": {"private": DRAFT}})
            assert "Draft text must be a string" in str(caught.value)
            assert activity.WARNING in str(caught.value)

    asyncio.run(run())
    assert PRIVATE not in stderr.read_text() and "DRAFT_SENTINEL" not in stderr.read_text()


def test_directory_identity_alias_cannot_bypass_activity_protection(
    configured: OutputPolicy, tmp_path: Path
) -> None:
    assert configured.activity.path is not None
    directory = configured.activity.path.parent
    alias = directory.with_name(directory.name.upper())
    if not alias.exists():
        pytest.skip("Filesystem has no case alias")
    with policy.POLICY_FILE.open("a") as handle:
        handle.write(f"[output]\ndirectory={json.dumps(str(alias))}\n")
    source = tmp_path / "input.txt"
    source.write_text(PRIVATE)
    with pytest.raises(ToolError, match="activity storage"):
        call("datafog_redact", path=str(source))
    assert not (directory / "input_redacted.txt").exists()
