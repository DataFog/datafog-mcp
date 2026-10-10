"""Exercise real Core pseudonyms through MCP without accessing an OS keychain."""

from __future__ import annotations

import asyncio
import csv
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


@pytest.mark.parametrize("suffix", ["txt", "csv", "tsv"])
def test_key_snapshot_is_reused(
    suffix: str, configured: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = configured
    if suffix != "txt":
        source = source.with_suffix("." + suffix)
        source.write_text("email\njane@example.com\njane@example.com\n")
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


@pytest.mark.parametrize("delimiter,suffix", [(",", "csv"), ("\t", "tsv")])
def test_table_pseudonyms_preserve_linkage_allowlists_and_structure(
    delimiter: str, suffix: str, configured: tuple[Path, Path]
) -> None:
    source, key = configured
    with policy.POLICY_FILE.open("a") as handle:
        handle.write('\n[allow.exact]\nEMAIL = ["public@example.com"]\nNPI = ["1234567893"]\n')
    source = source.with_suffix("." + suffix)
    original = (
        f"email{delimiter}NPI{delimiter}note\r\n"
        f'"jane@example.com"{delimiter}1234567893{delimiter}"a ""quoted"" note"\r\n'
        f'"jane@example.com"{delimiter}1234567893{delimiter}public@example.com\r\n'
    )
    source.write_bytes(original.encode())
    result = call(path=str(source), scope="customers", entity_types=["EMAIL", "NPI"])
    data = result.structured_content
    assert data is not None and data["counts"] == {"EMAIL": 2}
    output = Path(data["output_path"]).read_bytes().decode()
    rows = list(csv.reader(output.splitlines(), delimiter=delimiter))
    assert rows[1][0] == rows[2][0] and rows[1][0] != "jane@example.com"
    assert rows[1][1] == rows[2][1] == "1234567893"
    assert rows[1][2] == 'a "quoted" note'
    assert rows[2][2] == "public@example.com"
    assert output.count("\r\n") == 3
    assert source.read_bytes().decode() == original
    response = str(result.content) + json.dumps(data)
    assert rows[1][0] not in response
    assert key.read_text().strip() not in response
    # The same decoded value has the same pseudonym without CSV header context.
    plain = source.with_name("other.txt")
    plain.write_text("jane@example.com")
    plain_result = call(
        path=str(plain), scope="customers", entity_types=["EMAIL"]
    ).structured_content
    assert plain_result is not None
    assert Path(plain_result["output_path"]).read_text() == rows[1][0]


def test_pseudonymization_warns_on_missing_scope_without_widening_it(
    configured: tuple[Path, Path],
) -> None:
    source, _ = configured
    missing = source.parent / "missing"
    with policy.POLICY_FILE.open("a") as handle:
        handle.write(
            f'\n[scope]\nfolders = ["{missing}"]\n'
            '[workflow]\non_findings = "transform"\n'
            'transform_strategy = "pseudonymize"\npseudonym_scope = "customers"\n'
        )
    scanned = call("datafog_scan", path=str(source)).structured_content
    assert scanned is not None and scanned["warnings"]
    assert scanned["policy"]["scan_before_read"] is False
    assert scanned["policy"]["pseudonym_scope"] == "customers"
    result = call(path=str(source), scope="customers").structured_content
    assert result is not None and result["warnings"]
    assert "jane@example.com" not in Path(result["output_path"]).read_text()
    discovery = call("datafog_policy", path=str(missing / "future.txt")).structured_content
    assert discovery is not None and discovery["scan_before_read"] is False
    missing.mkdir()
    discovery = call("datafog_policy", path=str(missing / "future.txt")).structured_content
    assert discovery is not None and discovery["scan_before_read"] is True
    assert "warnings" not in discovery


@pytest.mark.parametrize(
    "input_format,text",
    [
        ("env", "EMAIL=jane@example.com\n"),
        ("sql", "SELECT 'jane@example.com';\n"),
        ("text", "jane@example.com\n"),
    ],
)
def test_pseudonymization_preserves_core_format_and_detector_selection(
    input_format: str, text: str, configured: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = configured
    source.write_text(text)
    original_scan = server.scan
    selections: list[Any] = []

    def scan(text: str, config: Any) -> Any:
        selections.append(config)
        return original_scan(text, config)

    monkeypatch.setattr(server, "scan", scan)
    result = call(
        path=str(source), scope="customers", entity_types=["EMAIL"], input_format=input_format
    )
    assert selections == [{"format": input_format, "entities": ["EMAIL"]}]
    data = result.structured_content
    assert data is not None and data["counts"] == {"EMAIL": 1}
    output = Path(data["output_path"]).read_text()
    assert "jane@example.com" not in output
    if input_format == "env":
        assert output.startswith("EMAIL=") and output.endswith("\n")
    if input_format == "sql":
        assert output.startswith("SELECT '") and output.endswith("';\n")


@pytest.mark.parametrize("size", [10_000_000, 10_000_001])
def test_pseudonymization_honors_current_byte_limit(
    size: int, configured: tuple[Path, Path]
) -> None:
    source, _ = configured
    tail = "\njane@example.com"
    source.write_bytes(b"x" * (size - len(tail)) + tail.encode())
    if size > 10_000_000:
        with pytest.raises(ToolError, match="over the 10000000 limit"):
            call(path=str(source), scope="customers", entity_types=["EMAIL"])
        assert not source.with_name("contacts_pseudonymized.txt").exists()
    else:
        result = call(
            path=str(source), scope="customers", entity_types=["EMAIL"]
        ).structured_content
        assert result is not None and result["entity_count"] == 1
        assert b"jane@example.com" not in Path(result["output_path"]).read_bytes()


@pytest.mark.parametrize("has_header", [True, False])
def test_pseudonymization_supports_explicit_headerless_tables(
    has_header: bool, configured: tuple[Path, Path]
) -> None:
    source, _ = configured
    source.write_text("jane@example.com\njane@example.com\n")
    data = call(
        path=str(source), scope="customers", input_format="csv", has_header=has_header
    ).structured_content
    assert data is not None and data["entity_count"] == (1 if has_header else 2)
    rows = list(csv.reader(Path(data["output_path"]).read_text().splitlines()))
    if has_header:
        assert rows[0] == ["jane@example.com"]
    else:
        assert rows[0] == rows[1] and rows[0] != ["jane@example.com"]


def test_pseudonymization_refuses_ambiguous_table_without_output(
    configured: tuple[Path, Path],
) -> None:
    source, key = configured
    source = source.with_suffix(".csv")
    source.write_text('email\n"jane@example.com\n')
    saved_key = key.read_bytes()
    with pytest.raises(ToolError, match="Malformed CSV"):
        call(path=str(source), scope="customers")
    assert not source.with_name("contacts_pseudonymized.csv").exists()
    assert key.read_bytes() == saved_key
