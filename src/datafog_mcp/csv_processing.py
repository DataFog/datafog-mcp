"""Comma/tab table processing with original-source finding locations.

Headers are explicit (on by default), not guessed. Cells are decoded before
scanning and only changed cells are serialized; untouched syntax stays intact.
"""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Protocol

from datafog_core import TextRange

from datafog_mcp.findings import CsvFinding, Located


class CsvError(ValueError):
    """A content-free CSV validation error safe to return to clients."""


class CellResult(Protocol):
    """Resolved transformation result from the shared detection pipeline."""

    @property
    def text(self) -> str: ...

    @property
    def transformations(self) -> Sequence[Located]: ...


CellProcessor = Callable[[str, int], CellResult]


@dataclass(frozen=True)
class CsvResult:
    text: str
    transformations: list[CsvFinding]


@dataclass(frozen=True)
class _Cell:
    start: int
    end: int
    content_start: int
    value: str
    escapes: tuple[int, ...]

    def source_offset(self, offset: int) -> int:
        # Each doubled quote contributes one extra raw character after its
        # decoded character. Offsets stay codepoints, including BOM and CRLF.
        return self.content_start + offset + bisect_left(self.escapes, offset)


def _rows(text: str, delimiter: str) -> Iterator[list[_Cell]]:
    record = 1
    row: list[_Cell] = []
    i = int(text.startswith("\ufeff"))
    length = len(text)
    if i == length:
        return

    def malformed(reason: str) -> CsvError:
        format_name = "CSV" if delimiter == "," else "TSV"
        return CsvError(
            f"Malformed {format_name} at record {record}, column {len(row) + 1}: {reason}. "
            'Rerun with input_format="text" for a plain-text scan; '
            "plain-text copies do not guarantee table structure."
        )

    while True:
        start = i
        escapes: list[int] = []
        if i < length and text[i] == '"':
            i += 1
            content_start = i
            pieces: list[str] = []
            decoded_length = 0
            segment = i
            while i < length:
                if text[i] != '"':
                    i += 1
                    continue
                pieces.append(text[segment:i])
                decoded_length += i - segment
                if i + 1 < length and text[i + 1] == '"':
                    escapes.append(decoded_length)
                    pieces.append('"')
                    decoded_length += 1
                    i += 2
                    segment = i
                    continue
                i += 1
                break
            else:
                raise malformed("unterminated quoted field")
            value = "".join(pieces)
            if i < length and text[i] not in delimiter + "\r\n":
                raise malformed("unexpected character after quoted field")
        else:
            content_start = i
            while i < length and text[i] not in delimiter + "\r\n":
                i += 1
            value = text[start:i]
        row.append(_Cell(start, i, content_start, value, tuple(escapes)))
        if i < length and text[i] == delimiter:
            i += 1
            continue
        # Trailing empty lines carry no cells. Preserve them in the source,
        # but do not report them as data records. Interior blank records stay
        # ambiguous between zero cells and a missing one-column value.
        if len(row) == 1 and row[0].start == row[0].end:
            if not text[i:].strip("\r\n"):
                return
            row = []
            raise malformed("interior blank records are unsupported")
        yield row
        record += 1
        row = []
        if i == length:
            break
        if text[i] == "\r" and i + 1 < length and text[i + 1] == "\n":
            i += 2
        else:
            i += 1
        if i == length:
            break
    return


def _encode(value: str) -> str:
    # Always quote changed cells, including empty strings. That keeps a
    # one-column removed value a record instead of an empty physical line.
    return '"' + value.replace('"', '""') + '"'


def process_csv(
    text: str,
    process_cell: CellProcessor,
    *,
    has_header: bool = True,
    delimiter: str = ",",
) -> CsvResult:
    """Process comma/tab tables, preserving untouched source syntax.

    Headers supply detection context but are excluded from matching and writes.
    The callback must retain the context and resolve only matches wholly inside
    the cell value. Locations are one-based data records and columns; offsets
    address the original raw source, including doubled quotes, BOM and CRLF.
    Ragged rows use corresponding headers where present; extra cells receive
    no header context. Trailing blank lines and literal quotes in unquoted
    cells are preserved. Error record numbers include the header, unlike finding
    records, which count only data records. Header text is never returned.
    """
    if delimiter not in (",", "\t"):
        raise CsvError("Unsupported CSV delimiter: use comma or tab")
    rows = _rows(text, delimiter)
    header_row = next(rows, []) if has_header else []
    headers = [cell.value for cell in header_row]
    findings: list[CsvFinding] = []
    patches: list[tuple[int, int, str]] = []
    for record, row in enumerate(rows, 1):
        for column, cell in enumerate(row, 1):
            header = headers[column - 1] if column <= len(headers) else ""
            prefix = f"{header}: " if header else ""
            result = process_cell(prefix + cell.value, len(prefix))
            if not result.text.startswith(prefix):
                raise CsvError("CSV processing failed: field context was modified")
            for item in result.transformations:
                begin = item.source_codepoint_range.start - len(prefix)
                end = item.source_codepoint_range.end - len(prefix)
                if not 0 <= begin < end <= len(cell.value):
                    raise CsvError("CSV processing failed: finding crosses a field boundary")
                findings.append(
                    CsvFinding(
                        item.entity_type,
                        TextRange(cell.source_offset(begin), cell.source_offset(end)),
                        record,
                        column,
                    )
                )
            value = result.text[len(prefix) :]
            if value != cell.value:
                patches.append((cell.start, cell.end, _encode(value)))
    chunks: list[str] = []
    previous = 0
    for start, end, replacement in patches:
        chunks.extend((text[previous:start], replacement))
        previous = end
    chunks.append(text[previous:])
    return CsvResult("".join(chunks), findings)
