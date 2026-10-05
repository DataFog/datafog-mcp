"""Policy snapshots are strict, private, and refreshed between operations."""

import os
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from datafog_mcp.policy import Policy, PolicyError, load_policy


def write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(text)
    return path


def test_missing_defaults(tmp_path: Path) -> None:
    path = tmp_path / "absent.toml"
    policy = load_policy(path)
    assert not policy.loaded
    assert policy.source_path == path
    assert policy.on_findings == "ask"
    assert policy.max_file_bytes == 100_000_000
    assert not policy.allow_exact
    assert not policy.logging_enabled
    assert not policy.pseudonymization_scopes


def test_snapshot_is_immutable_and_next_call_reloads(tmp_path: Path) -> None:
    path = write_policy(tmp_path, 'version = 1\n[allow.exact]\nEMAIL = ["Test@example.com"]')
    before = load_policy(path)
    with pytest.raises(FrozenInstanceError):
        before.version = 2  # type: ignore[misc]
    with pytest.raises(TypeError):
        before.allow_exact["EMAIL"] = ()  # type: ignore[index]
    path.write_text('version = 1\n[allow.exact]\nEMAIL = ["test@example.com"]')
    after = load_policy(path)
    assert before.allow_exact["EMAIL"] == ("Test@example.com",)
    assert after.allow_exact["EMAIL"] == ("test@example.com",)


def test_all_sections(tmp_path: Path) -> None:
    path = write_policy(
        tmp_path,
        """version = 1
[allow.exact]
EMAIL = ["example@example.com"]
PERSON = ["Synthetic Person"]
[output]
directory = "/tmp/outputs"
[workflow]
on_findings = "transform"
transform_strategy = "pseudonymize"
scope = "customers"
[scope]
folders = ["/tmp/data"]
extensions = [".CSV", ".txt"]
[logging]
enabled = true
path = "/tmp/activity.jsonl"
[limits]
max_file_bytes = 100000000
max_text_bytes = 2000
max_findings = 400
max_batch_files = 50
[pseudonymization.scopes.customers]
key_ref = "customers-v1"
backend = "file"
key_file = "/tmp/customers.key"
key_version = "2"
[pseudonymization.scopes.desktop]
key_ref = "desktop-v1"
[model]
bundle_directory = "/tmp/model"
timeout_seconds = 20
""",
    )
    policy = load_policy(path)
    assert policy.loaded
    assert policy.output_directory == Path("/tmp/outputs")
    assert policy.on_findings == "transform"
    assert policy.transform_scope == "customers"
    assert policy.scope_folders == (Path("/tmp/data"),)
    assert policy.scope_extensions == (".csv", ".txt")
    assert policy.logging_enabled
    assert policy.log_path == Path("/tmp/activity.jsonl")
    assert policy.max_text_bytes == 2000
    assert policy.max_findings == 400
    assert policy.max_batch_files == 50
    assert policy.pseudonymization_scopes["customers"].key_version == "2"
    assert policy.pseudonymization_scopes["desktop"].backend == "keyring"
    assert policy.model_bundle_directory == Path("/tmp/model")
    assert policy.model_timeout_seconds == 20


@pytest.mark.parametrize(
    "body",
    [
        "",
        "version = 2",
        "version = true",
        'version = "1"',
        'version = 1\nunknown = "PRIVATE_SENTINEL"',
        'version = 1\n[allow.exact]\nUNKNOWN = ["PRIVATE_SENTINEL"]',
        'version = 1\n[allow.exact]\nEMAIL = "PRIVATE_SENTINEL"',
        "version = 1\n[allow.exact]\nEMAIL = [1]",
        'version = 1\n[output]\ndirectory = "PRIVATE_SENTINEL"',
        'version = 1\n[scope]\nextensions = ["csv"]',
        'version = 1\n[scope]\nfolders = ["relative"]',
        'version = 1\n[logging]\nenabled = "yes"',
        "version = 1\n[logging]\ninclude_values = true",
        "version = 1\n[limits]\nmax_file_bytes = 0",
        "version = 1\n[limits]\nmax_file_bytes = true",
        "version = 1\n[limits]\nmax_text_bytes = 1.5",
        "version = 1\n[limits]\nmax_file_bytes = 1000000001",
        "version = 1\n[limits]\nmax_findings = 100001",
        "version = 1\n[limits]\nmax_batch_files = 10001",
        'version = 1\n[workflow]\non_findings = "PRIVATE_SENTINEL"',
        'version = 1\n[workflow]\ntransform_strategy = "pseudonymize"',
        'version = 1\n[workflow]\nscope = "unknown"',
        'version = 1\n[pseudonymization]\nscopes = "PRIVATE_SENTINEL"',
        'version = 1\n[pseudonymization.scopes.test]\nbackend = "file"\nkey_ref = "test"',
        'version = 1\n[pseudonymization.scopes.test]\nkey_ref = "../bad"',
        'version = 1\n[pseudonymization.scopes.test]\nkey_ref = "test"\nkey_file = "/tmp/key"',
        "version = 1\n[model]\ntimeout_seconds = 301",
        'version = 1\n[model]\nbundle_directory = "relative"',
        'version = 1\ninvalid = "PRIVATE_SENTINEL',
    ],
)
def test_invalid_policy_fails_without_values(tmp_path: Path, body: str) -> None:
    path = write_policy(tmp_path, body)
    with pytest.raises(PolicyError) as exc:
        load_policy(path)
    assert "PRIVATE_SENTINEL" not in str(exc.value)
    assert str(path) not in str(exc.value)


def test_paths_and_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    path = write_policy(tmp_path, 'version = 1\n[output]\ndirectory = "~/copies"')
    monkeypatch.setenv("DATAFOG_POLICY_PATH", str(path))
    assert load_policy().output_directory == tmp_path / "copies"
    monkeypatch.delenv("DATAFOG_POLICY_PATH")
    assert load_policy().source_path == tmp_path / ".config/datafog/policy.toml"
    monkeypatch.setenv("DATAFOG_POLICY_PATH", "relative")
    with pytest.raises(PolicyError):
        load_policy()


def test_io_failure_and_invalid_encoding(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_policy(tmp_path)
    path = tmp_path / "bad.toml"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(PolicyError):
        load_policy(path)
    path.write_bytes(b"x" * 1_048_577)
    with pytest.raises(PolicyError, match="size limit"):
        load_policy(path)


def test_policy_copies_input_collections() -> None:
    values = {"EMAIL": ("test@example.com",)}
    policy = Policy(allow_exact=values)
    values.clear()
    assert policy.allow_exact["EMAIL"] == ("test@example.com",)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
def test_policy_fifo_is_refused_without_waiting(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    os.mkfifo(path)
    with pytest.raises(PolicyError, match="regular file"):
        load_policy(path)
