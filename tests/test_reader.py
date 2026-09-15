"""Tests for datafog_mcp.reader."""

from __future__ import annotations

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
