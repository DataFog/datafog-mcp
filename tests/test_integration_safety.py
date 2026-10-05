"""Sensitive local configuration stays outside the data-plane operations."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import activity, server
from datafog_mcp.policy import Policy, PolicyError, PseudonymScope, load_policy


def private_file(path: Path, value: str = "PRIVATE_SENTINEL") -> Path:
    path.write_text(value)
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("protected_kind", ["policy", "key", "log"])
def test_protected_hardlink_alias_cannot_be_scanned(tmp_path: Path, protected_kind: str) -> None:
    protected = private_file(tmp_path / "protected")
    alias = tmp_path / "data.txt"
    os.link(protected, alias)
    policy = Policy(
        source_path=protected if protected_kind == "policy" else None,
        log_path=protected if protected_kind == "log" else tmp_path / "activity.jsonl",
        pseudonymization_scopes=(
            {"test": PseudonymScope("test", "file", protected)} if protected_kind == "key" else {}
        ),
    )
    with pytest.raises(ToolError, match="not data inputs"):
        asyncio.run(server._scan_file(str(alias), "findings", None, policy))


@pytest.mark.parametrize("protected_kind", ["policy", "key"])
def test_log_cannot_append_to_protected_file(tmp_path: Path, protected_kind: str) -> None:
    protected = private_file(tmp_path / "protected")
    policy = Policy(
        source_path=protected if protected_kind == "policy" else None,
        logging_enabled=True,
        log_path=protected,
        pseudonymization_scopes=(
            {"test": PseudonymScope("test", "file", protected)} if protected_kind == "key" else {}
        ),
    )
    assert activity.record(policy, "scan", "success", {}) == "unavailable"
    assert protected.read_text() == "PRIVATE_SENTINEL"


def test_log_refuses_hardlinked_destination(tmp_path: Path) -> None:
    protected = private_file(tmp_path / "source")
    alias = tmp_path / "activity.jsonl"
    os.link(protected, alias)
    policy = Policy(logging_enabled=True, log_path=alias)
    assert activity.record(policy, "scan", "success", {}) == "unavailable"
    assert protected.read_text() == "PRIVATE_SENTINEL"


def test_log_byte_limit_and_metadata_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "activity.jsonl"
    policy = Policy(logging_enabled=True, log_path=log)
    assert activity.record(policy, "scan", "success", {"EMAIL": 2}) == "recorded"
    payload = json.loads(log.read_text())
    assert set(payload) == {"time", "operation", "outcome", "counts"}
    assert payload["counts"] == {"EMAIL": 2}
    before = log.read_bytes()
    monkeypatch.setattr(activity, "_MAX_LOG_BYTES", len(before) + 1)
    assert activity.record(policy, "scan", "success", {}) == "unavailable"
    assert log.read_bytes() == before


def test_batch_enumeration_error_is_not_reported_as_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_walk(*args: object, **kwargs: object) -> object:
        error_callback = kwargs.get("onerror")
        if callable(error_callback):
            error_callback(PermissionError("PRIVATE_SENTINEL"))
        return iter(())

    monkeypatch.setattr(server.os, "walk", failed_walk)

    async def run() -> None:
        async with Client(server.mcp) as client:
            response = await client.call_tool(
                "datafog_scan_batch", {"paths": [str(tmp_path)], "recursive": True}
            )
        result = response.data
        assert result["error_count"] == 1
        assert result["files"][0]["status"] == "error"
        assert "PRIVATE_SENTINEL" not in str(result)

    asyncio.run(run())


def test_batch_does_not_enumerate_credential_directory(tmp_path: Path) -> None:
    denied = tmp_path / ".ssh"
    denied.mkdir()
    private_file(denied / "PRIVATE_SENTINEL")
    ordinary = private_file(tmp_path / "plain.txt", "ordinary")
    selected = server._batch_paths([str(tmp_path)], True, Policy())
    assert set(selected) == {ordinary, denied}
    assert all("PRIVATE_SENTINEL" not in str(path) for path in selected)


def test_dangling_policy_link_is_not_treated_as_missing_policy(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    policy.symlink_to(tmp_path / "nonexistent")
    with pytest.raises(PolicyError, match="target cannot be read"):
        load_policy(policy)
