"""
Safe file reading for scan requests.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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

    Parameters:
      path: Filesystem path to read.
      max_bytes: Size cap; larger files are refused.
    Returns:
      The decoded text and metadata describing the read.
    """
    resolved = Path(path).expanduser().resolve()

    if not resolved.exists():
        raise PathNotFound(f"no such file: {resolved}")
    if not resolved.is_file():
        raise NotARegularFile(f"not a regular file: {resolved}")

    size = resolved.stat().st_size  # Check size BEFORE reading into memory
    if size > max_bytes:
        raise FileTooLarge(f"{resolved} is {size} bytes, over the {max_bytes} limit")

    raw = resolved.read_bytes()

    # Check for NUL bytes
    if b"\x00" in raw:
        raise NotText(f"{resolved} seems to be binary, not text")

    return FileContent(
        text=raw.decode("utf-8", errors="replace"),
        path=resolved,
        size_bytes=size,
    )
