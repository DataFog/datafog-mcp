"""Key lifecycle tests never touch a real OS credential store."""

import asyncio
import base64
import os
import stat
import sys
from pathlib import Path

import pytest

from datafog_mcp import __main__, keys, policy
from datafog_mcp.keys import KeyStorageError, LocalKeyProvider, generate_scope_key
from datafog_mcp.policy import PseudonymScope


def resolve(scope: PseudonymScope) -> bytes:
    result = asyncio.run(LocalKeyProvider(scope).resolve_key(scope.key_ref, scope.key_version))
    return bytes(result["key"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX file storage")
def test_file_key_persists_and_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "private.key"
    scope = PseudonymScope("customers", "file", path)
    generate_scope_key(scope)
    raw = path.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    key = resolve(scope)
    assert len(key) == 32
    assert resolve(scope) == key
    with pytest.raises(KeyStorageError, match="already exists"):
        generate_scope_key(scope)
    assert path.read_bytes() == raw
    with pytest.raises(KeyStorageError, match="does not match"):
        asyncio.run(LocalKeyProvider(scope).resolve_key("other", "1"))
    with pytest.raises(KeyStorageError, match="does not match"):
        asyncio.run(LocalKeyProvider(scope).resolve_key("customers", "2"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX file storage")
def test_file_refuses_insecure_missing_invalid_and_links(tmp_path: Path) -> None:
    path = tmp_path / "key"
    scope = PseudonymScope("test", "file", path)
    with pytest.raises(KeyStorageError):
        resolve(scope)
    generate_scope_key(scope)
    path.chmod(0o644)
    with pytest.raises(KeyStorageError, match="0600"):
        resolve(scope)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(KeyStorageError):
        resolve(PseudonymScope("test", "file", link))
    link.unlink()
    os.link(path, link)
    with pytest.raises(KeyStorageError):
        resolve(scope)
    link.unlink()
    for payload in (b"private-sentinel", base64.b64encode(b"short"), b"x" * 129):
        path.write_bytes(payload)
        with pytest.raises(KeyStorageError) as exc:
            resolve(scope)
        assert "private-sentinel" not in str(exc.value)
    parent_link = tmp_path / "dir-link"
    parent_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(KeyStorageError):
        generate_scope_key(PseudonymScope("test", "file", parent_link / "new.key"))
    assert not (tmp_path / "new.key").exists()


class MockKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password


def test_os_store_lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy, "POLICY_FILE", tmp_path / "policy.toml")
    backend = MockKeyring()
    monkeypatch.setattr(keys, "_backend", lambda: backend)
    scope = PseudonymScope("customers")
    with pytest.raises(KeyStorageError, match="missing"):
        resolve(scope)
    generate_scope_key(scope)
    first = resolve(scope)
    assert len(first) == 32
    assert resolve(scope) == first
    with pytest.raises(KeyStorageError, match="already exists"):
        generate_scope_key(scope)
    assert resolve(scope) == first
    generate_scope_key(PseudonymScope("other"))
    assert resolve(PseudonymScope("other")) != first
    lock = tmp_path / ".key-setup.lock"
    lock.mkdir()
    with pytest.raises(KeyStorageError, match="stale lock"):
        generate_scope_key(PseudonymScope("third"))


def test_os_store_rejects_fallback_and_sanitizes_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keys.keyring, "get_keyring", MockKeyring)
    with pytest.raises(KeyStorageError, match="OS credential-store"):
        resolve(PseudonymScope("test"))

    def unavailable() -> None:
        raise RuntimeError("PRIVATE_SENTINEL")

    monkeypatch.setattr(keys, "_backend", unavailable)
    with pytest.raises(KeyStorageError) as exc:
        resolve(PseudonymScope("test"))
    assert "PRIVATE_SENTINEL" not in str(exc.value)


def test_cli_creates_configured_key_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "key"
    policy = tmp_path / "policy.toml"
    policy.write_text(
        'version = 1\n[pseudonymization.scopes.test]\nkey_ref = "test"\n'
        f'backend = "file"\nkey_file = "{path}"\n'
    )
    monkeypatch.setattr(keys.policy, "POLICY_FILE", policy)
    monkeypatch.setattr(sys, "argv", ["datafog-mcp", "keys", "create", "test"])
    __main__.main()
    output = capsys.readouterr().out
    assert "key created" in output
    assert path.read_text().strip() not in output
    with pytest.raises(SystemExit, match="already exists"):
        __main__.main()
    monkeypatch.setattr(sys, "argv", ["datafog-mcp", "keys", "create", "unknown"])
    with pytest.raises(SystemExit, match="not configured"):
        __main__.main()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file storage")
def test_core_uses_persistent_provider_for_cross_file_pseudonyms(tmp_path: Path) -> None:
    from datafog_core import PrivacyManager, scan

    scope = PseudonymScope("customers", "file", tmp_path / "customers.key")
    other = PseudonymScope("separate", "file", tmp_path / "separate.key")
    generate_scope_key(scope)
    generate_scope_key(other)

    async def pseudonymize(text: str, selected: PseudonymScope) -> str:
        manager = PrivacyManager(provider=LocalKeyProvider(selected))
        result = await manager.transform(
            text,
            scan(text),
            {
                "default": {
                    "strategy": "pseudonymize",
                    "key_ref": selected.key_ref,
                    "key_version": selected.key_version,
                }
            },
        )
        return result.text

    first = asyncio.run(pseudonymize("jane@example.com", scope))
    second = asyncio.run(pseudonymize("jane@example.com", scope))
    separated = asyncio.run(pseudonymize("jane@example.com", other))
    assert first == second
    assert first != separated
    assert "jane@example.com" not in first


@pytest.mark.skipif(os.name != "posix", reason="POSIX file storage")
@pytest.mark.parametrize("kind", ["fifo", "directory", "owner"])
def test_refuses_nonregular_or_other_owner_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    path = tmp_path / "key"
    scope = PseudonymScope("test", "file", path)
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "directory":
        path.mkdir(mode=0o600)
    else:
        generate_scope_key(scope)
        actual = os.getuid()
        monkeypatch.setattr(keys.os, "getuid", lambda: actual + 1)
    with pytest.raises(KeyStorageError):
        resolve(scope)


def test_file_setup_removes_partial_key_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "key"

    def fail(_: int) -> None:
        raise OSError("PRIVATE_SENTINEL")

    monkeypatch.setattr(keys.os, "fsync", fail)
    with pytest.raises(KeyStorageError) as error:
        generate_scope_key(PseudonymScope("test", "file", path))
    assert "PRIVATE_SENTINEL" not in str(error.value)
    assert not path.exists()


def test_os_failure_never_creates_file_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(policy, "POLICY_FILE", tmp_path / "policy.toml")

    class LockedStore(MockKeyring):
        def get_password(self, service: str, username: str) -> str | None:
            raise RuntimeError("PRIVATE_SENTINEL")

    monkeypatch.setattr(keys, "_backend", LockedStore)
    scope = PseudonymScope("test")
    for action in (resolve, generate_scope_key):
        with pytest.raises(KeyStorageError) as error:
            action(scope)
        assert "PRIVATE_SENTINEL" not in str(error.value)
    assert list(tmp_path.iterdir()) == []
