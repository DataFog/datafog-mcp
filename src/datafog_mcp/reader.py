"""
Safe file reading for scan and redaction requests.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .paths import resolve_input, resolve_output


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
    resolved = resolve_input(path)

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


def write_text_file(path: str | Path, text: str, beside: Path) -> Path:
    """
    Write text to a file the server is allowed to create.

    Creates exclusively. Refuses to overwrite and refuses any destination
    outside the directory of input it derives from.

    Parameters:
      path: Destination path.
      text: Content to write.
      beside: The resolved input path bounding where output may go.
    Returns:
      The resolved path that was written.
    """
    resolved = resolve_output(str(path), beside)

    try:
        with resolved.open("x", encoding="utf-8") as handle:
            handle.write(text)
    except FileExistsError as exc:
        raise FileExists(f"{resolved} already exists") from exc

    return resolved
