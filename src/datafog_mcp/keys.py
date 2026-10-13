"""Local pseudonymization keys, created only by explicit setup.

Deleting a key and creating a replacement breaks joins with previous outputs.
No backend fallback, implicit generation, or automatic rotation is permitted.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

import keyring

from . import policy
from .policy import PseudonymScope

if TYPE_CHECKING:
    from collections.abc import Iterator

    from datafog_core import _ResolvedKey

_SERVICE = "datafog-mcp.pseudonymization"
_OS_BACKENDS = {
    ("keyring.backends.macOS", "Keyring"),
    ("keyring.backends.Windows", "WinVaultKeyring"),
    ("keyring.backends.SecretService", "Keyring"),
    ("keyring.backends.libsecret", "Keyring"),
    ("keyring.backends.kwallet", "DBusKeyring"),
    ("keyring.backends.kwallet", "DBusKeyringKWallet4"),
}


class KeyStorageError(ValueError):
    """A sanitized local key-storage failure."""


class _CredentialBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...


def _backend() -> _CredentialBackend:
    backend = keyring.get_keyring()
    if (type(backend).__module__, type(backend).__name__) not in _OS_BACKENDS:
        raise KeyStorageError(
            "An OS credential-store backend is required; configure it explicitly."
        )
    return cast(_CredentialBackend, backend)


def _account(scope: PseudonymScope) -> str:
    return f"{scope.key_ref}:{scope.key_version}"


def _decode(encoded: str | bytes) -> bytes:
    try:
        key = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise KeyStorageError("Stored pseudonymization key is invalid.") from None
    if len(key) != 32:
        raise KeyStorageError("Stored pseudonymization key is invalid.")
    return key


@contextmanager
def _parent_fd(path: Path) -> Iterator[int]:
    # Walk with no-follow directory handles, preventing parent symlink races too.
    if os.name != "posix" or not path.is_absolute() or ".." in path.parts:
        raise KeyStorageError("File key storage requires an absolute POSIX path without symlinks.")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def _read_file(path: Path) -> bytes:
    with _parent_fd(path) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise KeyStorageError(
                    "Key file must be a private, owner-controlled regular file (0600)."
                )
            if info.st_size > 128:
                raise KeyStorageError("Stored pseudonymization key is invalid.")
            return _decode(handle.read(129).strip())


def _resolve(scope: PseudonymScope) -> bytes:
    try:
        if scope.backend == "file":
            if scope.key_file is None:
                raise KeyStorageError("File key storage requires a configured key file.")
            return _read_file(scope.key_file)
        encoded = _backend().get_password(_SERVICE, _account(scope))
        if encoded is None:
            raise KeyStorageError("Pseudonymization key is missing; run explicit key setup.")
        return _decode(encoded)
    except KeyStorageError:
        raise
    except Exception:
        raise KeyStorageError(
            "Pseudonymization key could not be retrieved from local storage."
        ) from None


class LocalKeyProvider:
    def __init__(self, scope: PseudonymScope) -> None:
        self.scope = scope
        self._key: bytes | None = None
        self._lock = asyncio.Lock()

    async def resolve_key(self, key_ref: str, key_version: str | None, /) -> _ResolvedKey:
        if key_ref != self.scope.key_ref or key_version not in (None, self.scope.key_version):
            raise KeyStorageError(
                "Pseudonymization key reference or version does not match the scope."
            )
        async with self._lock:
            if self._key is None:
                self._key = await asyncio.to_thread(_resolve, self.scope)
            return {"key": self._key, "resolved_version": self.scope.key_version}


@contextmanager
def _setup_lock() -> Iterator[None]:
    """Serialize explicit setup without modifying an existing lock or its target."""
    directory = policy.POLICY_FILE.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink():
        raise KeyStorageError("Key setup state directory must not be a symlink.")
    lock = directory / ".key-setup.lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise KeyStorageError(
            "Key setup is already running or left a stale lock; inspect .key-setup.lock locally."
        ) from None
    try:
        yield
    finally:
        lock.rmdir()


def generate_scope_key(scope: PseudonymScope) -> None:
    """Create a 256-bit key. Existing keys are never intentionally replaced."""
    encoded = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    try:
        if scope.backend == "file":
            if scope.key_file is None:
                raise KeyStorageError("File key storage requires a configured key file.")
            with _parent_fd(scope.key_file) as parent:
                fd = os.open(
                    scope.key_file.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
                try:
                    with os.fdopen(fd, "w", encoding="ascii") as handle:
                        os.fchmod(handle.fileno(), 0o600)
                        handle.write(encoded + "\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                except Exception:
                    os.unlink(scope.key_file.name, dir_fd=parent)
                    raise
            return
        with _setup_lock():
            backend = _backend()
            account = _account(scope)
            if backend.get_password(_SERVICE, account) is not None:
                raise KeyStorageError("Pseudonymization key already exists; refusing replacement.")
            backend.set_password(_SERVICE, account, encoded)
    except FileExistsError:
        raise KeyStorageError(
            "Pseudonymization key already exists; refusing replacement."
        ) from None
    except KeyStorageError:
        raise
    except Exception:
        raise KeyStorageError(
            "Pseudonymization key could not be created in local storage."
        ) from None
