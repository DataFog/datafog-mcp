"""Exercise real Core pseudonyms through MCP without accessing an OS keychain."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import keys, policy, server
from datafog_mcp.keys import generate_scope_key
from datafog_mcp.policy import PseudonymScope


@pytest.fixture
def configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    key = tmp_path / "customers.key"
    config = tmp_path / "policy.toml"
    config.write_text(
        'version = 1\n[pseudonymization.scopes.customers]\nkey_ref = "customers"\n'
        f'backend = "file"\nkey_file = "{key}"\n'
    )
    monkeypatch.setattr(policy, "POLICY_FILE", config)
    generate_scope_key(PseudonymScope("customers", "file", key))
    source = tmp_path / "contacts.txt"
    source.write_text("jane@example.com jane@example.com public@example.com\n")
    return source, key


def call(tool: str = "datafog_pseudonymize", **arguments: Any) -> Any:
    async def run() -> Any:
        async with Client(server.mcp) as client:
            return await client.call_tool(tool, arguments)

    return asyncio.run(run())


def test_linkage_metadata_and_no_overwrite(configured: tuple[Path, Path]) -> None:
    source, key = configured
    original = source.read_bytes()
    saved_key = key.read_bytes()
    first = call(path=str(source), scope="customers")
    data = first.structured_content
    assert data is not None
    output = Path(data["output_path"])
    text = output.read_text()
    parts = text.split()
    assert parts[0] == parts[1] and parts[0] != parts[2]
    assert "jane@example.com" not in text
    assert data["strategy"] == "pseudonymize"
    assert data["counts"] == {"EMAIL": 3}
    assert data["entity_count"] == 3
    response = str(first.content) + json.dumps(data)
    assert "jane@example.com" not in response
    assert saved_key.decode().strip() not in response
    assert parts[0] not in response
    second = source.with_name("second.txt")
    second.write_bytes(original)
    other = call(path=str(second), scope="customers").structured_content
    assert other is not None
    assert Path(other["output_path"]).read_text() == text
    with pytest.raises(ToolError):
        call(path=str(source), scope="customers")
    assert output.read_text() == text
    assert source.read_bytes() == original and key.read_bytes() == saved_key


def test_new_process_uses_same_stored_key(configured: tuple[Path, Path]) -> None:
    source, key = configured
    result = call(path=str(source), scope="customers").structured_content
    assert result is not None
    program = """import asyncio, sys
from pathlib import Path
from datafog_core import PrivacyManager, scan
from datafog_mcp.keys import LocalKeyProvider
from datafog_mcp.policy import PseudonymScope
async def run():
    scope = PseudonymScope("customers", "file", Path(sys.argv[1]))
    text = Path(sys.argv[2]).read_text()
    result = await PrivacyManager(provider=LocalKeyProvider(scope)).transform(
        text, scan(text), {"default": {"strategy": "pseudonymize",
                                     "key_ref": "customers", "key_version": "1"}})
    print(result.text, end="")
asyncio.run(run())
"""
    child = subprocess.run(
        [sys.executable, "-c", program, str(key), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert child.stdout == Path(result["output_path"]).read_text()
    assert not child.stderr


def test_allowlist_and_workflow_discovery(configured: tuple[Path, Path]) -> None:
    source, key = configured
    with policy.POLICY_FILE.open("a") as handle:
        handle.write(
            '\n[allow.exact]\nEMAIL = ["public@example.com"]\n'
            '[workflow]\non_findings = "transform"\n'
            'transform_strategy = "pseudonymize"\npseudonym_scope = "customers"\n'
        )
    discovery = call("datafog_policy").structured_content
    assert discovery is not None
    assert discovery["pseudonymization_scopes"] == ["customers"]
    assert discovery["workflow"]["pseudonym_scope"] == "customers"
    assert str(key) not in json.dumps(discovery)
    assert "public@example.com" not in json.dumps(discovery)
    scanned = call("datafog_scan", path=str(source)).structured_content
    assert scanned is not None
    assert scanned["policy"]["pseudonym_scope"] == "customers"
    result = call(path=str(source), scope="customers").structured_content
    assert result is not None and result["entity_count"] == 2
    text = Path(result["output_path"]).read_text()
    assert "public@example.com" in text and "jane@example.com" not in text


@pytest.mark.parametrize("failure", ["missing", "invalid", "permissions", "unknown"])
@pytest.mark.parametrize("text", ["jane@example.com", "no detections here"])
def test_no_key_never_creates_copy(configured: tuple[Path, Path], failure: str, text: str) -> None:
    source, key = configured
    source.write_text(text)
    if failure == "missing":
        key.unlink()
    elif failure == "invalid":
        key.write_text("PRIVATE_SENTINEL")
    elif failure == "permissions":
        key.chmod(0o644)
    with pytest.raises(ToolError) as error:
        call(path=str(source), scope="unknown" if failure == "unknown" else "customers")
    assert "PRIVATE_SENTINEL" not in str(error.value)
    assert not source.with_name("contacts_pseudonymized.txt").exists()
    assert source.read_text() == text
    if failure == "missing":
        assert not key.exists()


@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink"])
@pytest.mark.parametrize(
    "tool",
    [
        "datafog_scan",
        "datafog_redact",
        "datafog_mask",
        "datafog_remove",
        "datafog_pseudonymize",
        "datafog_policy",
    ],
)
def test_configured_key_cannot_be_read_as_data(
    configured: tuple[Path, Path], alias: str, tool: str
) -> None:
    source, key = configured
    target = key
    if alias != "direct":
        target = source.with_name("alias.txt")
        if alias == "symlink":
            target.symlink_to(key)
        else:
            os.link(key, target)
    arguments: dict[str, Any] = {"path": str(target)}
    if tool == "datafog_pseudonymize":
        arguments["scope"] = "customers"
    with pytest.raises(ToolError):
        call(tool, **arguments)


@pytest.mark.parametrize("failure_point", ["scan", "engine", "write", "storage"])
def test_failures_never_leak_values_or_keys(
    configured: tuple[Path, Path],
    failure_point: str,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    source, key = configured
    secret = key.read_text().strip()

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(f"jane@example.com {secret}")

    async def async_fail(*args: Any, **kwargs: Any) -> Any:
        return fail()

    if failure_point == "engine":
        monkeypatch.setattr(server.PrivacyManager, "transform", async_fail)
    elif failure_point == "storage":
        monkeypatch.setattr(keys, "_read_file", fail)
    else:
        monkeypatch.setattr(server, "scan" if failure_point == "scan" else "write_text_file", fail)
    with pytest.raises(ToolError) as error:
        call(path=str(source), scope="customers")
    captured = capfd.readouterr()
    all_errors = str(error.value) + captured.out + captured.err + caplog.text
    assert secret not in all_errors and "jane@example.com" not in all_errors
    assert not source.with_name("contacts_pseudonymized.txt").exists()


def test_key_snapshot_is_reused(
    configured: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = configured
    original = keys._read_file
    reads: list[Path] = []

    def once(path: Path) -> bytes:
        reads.append(path)
        assert len(reads) == 1
        return original(path)

    monkeypatch.setattr(keys, "_read_file", once)
    call(path=str(source), scope="customers")
    assert len(reads) == 1


@pytest.mark.parametrize(
    "case",
    [
        'backend = "automatic"',
        'key_file = "/a/key"',
        'backend = "file"',
        'backend = "file"\nkey_file = "relative.key"',
        'backend = "file"\nkey_file = "/a/../key"',
        'key = "PRIVATE_SENTINEL"',
        'key_version = "bad version"',
    ],
)
def test_invalid_scope_configuration_is_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    config = tmp_path / "policy.toml"
    config.write_text('version = 1\n[pseudonymization.scopes.test]\nkey_ref = "test"\n' + case)
    monkeypatch.setattr(policy, "POLICY_FILE", config)
    with pytest.raises(policy.OutputPolicyError) as error:
        policy.load_output_policy()
    assert "PRIVATE_SENTINEL" not in str(error.value)


@pytest.mark.parametrize("scope_line", ["", 'pseudonym_scope = "missing"'])
def test_workflow_requires_configured_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope_line: str
) -> None:
    config = tmp_path / "policy.toml"
    config.write_text('version = 1\n[workflow]\ntransform_strategy = "pseudonymize"\n' + scope_line)
    monkeypatch.setattr(policy, "POLICY_FILE", config)
    with pytest.raises(policy.OutputPolicyError):
        policy.load_output_policy()


def test_fixed_destination_and_entity_selection(configured: tuple[Path, Path]) -> None:
    source, key = configured
    output_dir = source.parent / "copies"
    output_dir.mkdir()
    with policy.POLICY_FILE.open("a") as handle:
        handle.write(f'\n[output]\ndirectory = "{output_dir}"\n')
    result = call(path=str(source), scope="customers", entity_types=["SSN"]).structured_content
    assert result is not None and result["entity_count"] == 0
    assert Path(result["output_path"]).parent == output_dir
    assert Path(result["output_path"]).read_text() == source.read_text()
    for destination in (
        source,
        key,
        source.parent / "elsewhere.txt",
        output_dir / "sub" / "copy.txt",
    ):
        with pytest.raises(ToolError):
            call(path=str(source), scope="customers", output_path=str(destination))


def test_missing_key_does_not_prevent_scan_or_discovery(configured: tuple[Path, Path]) -> None:
    source, key = configured
    key.unlink()
    assert call("datafog_policy").structured_content["pseudonymization_scopes"] == ["customers"]
    assert call("datafog_scan", path=str(source)).structured_content["entity_count"] == 3


def test_key_destination_is_reserved_before_setup(configured: tuple[Path, Path]) -> None:
    source, key = configured
    key.unlink()
    with pytest.raises(ToolError, match="key files"):
        call("datafog_redact", path=str(source), output_path=str(key))
    assert not key.exists()


def test_pseudonym_copy_permissions_and_roots(
    configured: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from datafog_mcp.paths import ALLOWED_ROOTS_VAR

    source, _ = configured
    source.chmod(0o600)
    data = call(path=str(source), scope="customers").structured_content
    assert data is not None
    assert Path(data["output_path"]).stat().st_mode & 0o777 == 0o600
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, "")
    with pytest.raises(ToolError):
        call(path=str(source), scope="customers", output_path=str(source.with_name("refused.txt")))
    assert not source.with_name("refused.txt").exists()
