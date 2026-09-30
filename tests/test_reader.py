"""Tests for datafog_mcp.reader."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from datafog_mcp.reader import (
    FileExists,
    FileTooLarge,
    NotARegularFile,
    NotText,
    PathNotFound,
    read_text_file,
    write_text_file,
)

_LIMIT = 1024

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")


def test_reads_utf8_text(tmp_path: Path) -> None:
    """A plain UTF-8 file comes back decoded, with its size."""
    target = tmp_path / "export.csv"
    target.write_text("name,email\nJosh,josh@example.com\n")

    result = read_text_file(str(target), _LIMIT)

    assert "josh@example.com" in result.text
    assert result.size_bytes == target.stat().st_size
    assert result.path == target.resolve()


def test_empty_file_is_readable(tmp_path: Path) -> None:
    """An empty file yields empty text rather than an error."""
    target = tmp_path / "empty.csv"
    target.write_bytes(b"")

    result = read_text_file(str(target), _LIMIT)

    assert result.text == ""
    assert result.size_bytes == 0


def test_missing_path(tmp_path: Path) -> None:
    """A path that does not exist raises PathNotFound."""
    with pytest.raises(PathNotFound):
        read_text_file(str(tmp_path / "absent.csv"), _LIMIT)


def test_directory_is_rejected(tmp_path: Path) -> None:
    """A directory raises NotARegularFile, not PathNotFound."""
    with pytest.raises(NotARegularFile):
        read_text_file(str(tmp_path), _LIMIT)


def test_oversized_file_is_refused(tmp_path: Path) -> None:
    """A file above the ceiling raises FileTooLarge."""
    target = tmp_path / "big.csv"
    target.write_bytes(b"x" * (_LIMIT + 1))

    with pytest.raises(FileTooLarge):
        read_text_file(str(target), _LIMIT)


def test_file_at_limit_is_allowed(tmp_path: Path) -> None:
    """The ceiling is inclusive; only files strictly over it fail."""
    target = tmp_path / "exact.csv"
    target.write_bytes(b"x" * _LIMIT)

    assert read_text_file(str(target), _LIMIT).size_bytes == _LIMIT


def test_binary_file_is_rejected(tmp_path: Path) -> None:
    """NUL bytes mark a file as binary and unscannable."""
    target = tmp_path / "export.zip"
    target.write_bytes(b"PK\x03\x04\x00\x00rest of an archive")

    with pytest.raises(NotText):
        read_text_file(str(target), _LIMIT)


def test_invalid_utf8_without_nul_is_decoded(tmp_path: Path) -> None:
    """Latin-1 bytes decode with replacement instead of raising."""
    target = tmp_path / "latin1.csv"
    target.write_bytes("name\nJos\xe9\n".encode("latin-1"))

    result = read_text_file(str(target), _LIMIT)

    assert "Jos" in result.text


def test_dangling_symlink_destination_is_refused(tmp_path: Path) -> None:
    """
    A symlink at the destination is not followed, even when dangling.

    Path.exists() reports False for a dangling link, so a check-then-
    write would follow it and create the target. Exclusive creation
    refuses the link itself.
    """
    source = tmp_path / "input.txt"
    source.write_text("", encoding="utf-8")
    target = tmp_path / "planted_target"
    link = tmp_path / "out.txt"
    link.symlink_to(target)

    with pytest.raises(FileExists):
        write_text_file(link, "payload", beside=source)

    assert not target.exists()


def test_symlink_to_existing_file_is_not_written_through(
    tmp_path: Path,
) -> None:
    """The link's target is untouched."""
    source = tmp_path / "input.txt"
    source.write_text("", encoding="utf-8")
    target = tmp_path / "victim.txt"
    target.write_text("original", encoding="utf-8")
    link = tmp_path / "out.txt"
    link.symlink_to(target)

    with pytest.raises(FileExists):
        write_text_file(link, "payload", beside=source)

    assert target.read_text(encoding="utf-8") == "original"


def _mode(path: Path) -> int:
    """
    Read a file's permission bits.

    Parameters:
      path: The file to inspect.
    Returns:
      The permission bits, without the file type.
    """
    return stat.S_IMODE(path.stat().st_mode)


@posix_only
@pytest.mark.parametrize(
    ("source_mode", "expected"),
    [(0o600, 0o600), (0o640, 0o640), (0o644, 0o644), (0o755, 0o644)],
    ids=["0600", "0640", "0644", "0755"],
)
@pytest.mark.usefixtures("umask_022")
def test_output_takes_the_input_permissions(
    tmp_path: Path, source_mode: int, expected: int
) -> None:
    """
    A copy is never more readable than its source.

    The copy may still hold identifiers the detectors missed, so it is no
    safer to widen than the original. Execute bits are dropped, since a
    transformed text file is never meant to run.

    Parameters:
      tmp_path: Holds the source and the copy.
      source_mode: Permission bits given to the source.
      expected: Permission bits the copy should end up with.
    """
    source = tmp_path / "in.csv"
    source.write_text("x", encoding="utf-8")
    source.chmod(source_mode)

    written = write_text_file(tmp_path / "out.csv", "y", beside=source)

    assert _mode(written) == expected


@posix_only
def test_umask_can_still_narrow_the_copy(tmp_path: Path) -> None:
    """
    A stricter umask makes the copy stricter than its source, never looser.

    Parameters:
      tmp_path: Holds the source and the copy.
    """
    source = tmp_path / "in.csv"
    source.write_text("x", encoding="utf-8")
    source.chmod(0o644)

    previous = os.umask(0o077)
    try:
        written = write_text_file(tmp_path / "out.csv", "y", beside=source)
    finally:
        os.umask(previous)

    assert _mode(written) == 0o600


def test_failed_write_leaves_no_file(tmp_path: Path) -> None:
    """
    A write that fails after the file is created leaves nothing behind.

    Otherwise an empty or truncated copy would sit at the output path looking
    like a finished result. A lone surrogate cannot be encoded as UTF-8, so the
    write fails after the destination already exists.

    Parameters:
      tmp_path: Holds the source and the attempted copy.
    """
    source = tmp_path / "in.csv"
    source.write_text("x", encoding="utf-8")
    destination = tmp_path / "out.csv"

    with pytest.raises(UnicodeEncodeError):
        write_text_file(destination, "partial\ud800", beside=source)

    assert not destination.exists()
