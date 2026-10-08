"""
Safe file reading for scan and redaction requests.
"""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .paths import resolve_input, resolve_output
from .policy import OutputPolicy

# Byte-order marks of encodings this server does not read. UTF-32 LE's mark
# begins with UTF-16 LE's, so these three cover both widths and byte orders.
_WIDE_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")


class ReadError(Exception):
    """Base class for file-read failures."""


class PathNotFound(ReadError):
    """The path does not exist."""


class NotARegularFile(ReadError):
    """The path is a directory, device, socket, or similar."""


class FileTooLarge(ReadError):
    """The file is too large."""


class NotText(ReadError):
    """The file is binary or otherwise not scannable as text."""


class WriteError(Exception):
    """Base class for file-write failures."""


class FileExists(WriteError):
    """The destination already exists."""


class InsufficientSpace(WriteError):
    """The destination filesystem cannot hold the transformed copy."""


@dataclass(frozen=True)
class FileContent:
    """
    Decoded text of a file, with the metadata of the read.
    """

    text: str
    path: Path
    size_bytes: int


def read_text_file(path: str, max_bytes: int) -> FileContent:
    """
    Read a file as UTF-8 text. Refuse anything unscannable.

    The stat() check fails fast with the exact size, but the read itself
    enforces the limit: it takes at most one byte more than the cap, so a file
    that grows after the check, or reports a size it does not have, still
    cannot exceed it.

    Text must be valid UTF-8.

    Parameters:
      path: Filesystem path to read.
      max_bytes: Size cap; larger files are refused.
    Returns:
      The decoded text and metadata describing the read.
    """
    resolved = resolve_input(path)

    if not resolved.exists():
        raise PathNotFound(f"no such file: {resolved}")
    if not resolved.is_file():
        raise NotARegularFile(f"not a regular file: {resolved}")

    size = resolved.stat().st_size  # Check size BEFORE reading into memory
    if size > max_bytes:
        raise FileTooLarge(f"{resolved} is {size} bytes, over the {max_bytes} limit")

    with resolved.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise FileTooLarge(f"{resolved} is over the {max_bytes} byte limit")

    # Checked before NUL bytes, which wide encodings use for ASCII text
    if raw.startswith(_WIDE_BOMS):
        raise NotText(f"{resolved} is UTF-16 or UTF-32 encoded; only UTF-8 is supported")

    if b"\x00" in raw:
        raise NotText(f"{resolved} seems to be binary, not text")

    # from None: a UnicodeDecodeError holds the whole input as its .object
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NotText(
            f"{resolved} is not valid UTF-8 (first invalid byte at offset {exc.start})"
        ) from None

    return FileContent(text=text, path=resolved, size_bytes=len(raw))


def write_text_file(
    path: str | Path, text: str, beside: Path, copy_policy: OutputPolicy | None = None
) -> Path:
    """
    Write text to a file the server is allowed to create.

    Creates exclusively. Refuses to overwrite and refuses any destination
    outside the owner-configured output directory, or the input's directory
    when none is configured. Checks free space before creating a copy.

    The copy takes the input's permission bits, less execute and special bits,
    and the umask can narrow them further. A copy may still hold identifiers
    the detectors missed, so it is never made more readable than its source.

    If the write fails after the file is created, the file is removed, so a
    failure never leaves an empty or truncated copy that looks finished.

    Parameters:
      path: Destination path.
      text: Content to write.
      beside: The resolved input path bounding where output may go.
      copy_policy: A request's output policy snapshot, or None to load it now.
    Returns:
      The resolved path that was written.
    """
    resolved = resolve_output(str(path), beside, copy_policy)
    mode = stat.S_IMODE(beside.stat().st_mode) & 0o666

    # Newline translation is disabled to preserve table line endings.
    # Check exactly the transformed UTF-8 bytes that will be written.
    required = len(text.encode("utf-8"))
    try:
        available = shutil.disk_usage(resolved.parent).free
    except OSError:
        raise WriteError("cannot check free space for the output directory") from None
    if available < required:
        raise InsufficientSpace(
            f"not enough free space for the copy: needs {required} bytes, "
            f"{available} bytes available"
        )

    try:
        descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError as exc:
        raise FileExists(f"{resolved} already exists") from exc

    # From here the file is ours, so removing it on failure is safe
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except BaseException:
        resolved.unlink(missing_ok=True)
        raise

    return resolved
