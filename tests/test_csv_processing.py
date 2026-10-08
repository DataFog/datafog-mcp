"""CSV contracts: structural preservation and locations in original text."""

from __future__ import annotations

import csv
import io
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from datafog_core import TextRange, scan, transform

from datafog_mcp.config import Strategy, transform_config
from datafog_mcp.csv_processing import CellResult, CsvError, process_csv
from datafog_mcp.findings import Located


def core_processor(strategy: Strategy = "redact") -> Callable[[str, int], CellResult]:
    def process(text: str, value_start: int) -> CellResult:
        found = [item for item in scan(text) if item.codepoint_range.start >= value_start]
        return transform(text, found, transform_config(strategy))

    return process


def read_rows(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text.lstrip("\ufeff"), newline="")))


@pytest.mark.parametrize("strategy", ["redact", "mask", "remove"])
def test_real_core_transforms_preserve_csv_structure(strategy: Strategy) -> None:
    source = (
        "\ufeffname,email,notes,email\r\n"
        'José,jane@example.com,"comma, and ""quote""\r\nnext line",other@example.com\r\n'
        "李,repeat@example.com,,jane@example.com\r\n"
    )
    result = process_csv(source, core_processor(strategy))
    before, after = read_rows(source), read_rows(result.text)
    assert len(after) == len(before)
    assert after[0] == before[0]
    assert [len(row) for row in after] == [4, 4, 4]
    assert [row[0] for row in after] == [row[0] for row in before]
    assert [row[2] for row in after] == [row[2] for row in before]
    assert result.text.startswith("\ufeff")
    assert len(result.transformations) == 4
    for item in result.transformations:
        assert item.entity_type == "EMAIL"
        assert source[item.source_codepoint_range.start : item.source_codepoint_range.end].endswith(
            "@example.com"
        )
    assert [(item.record, item.column) for item in result.transformations] == [
        (1, 2),
        (1, 4),
        (2, 2),
        (2, 4),
    ]


@dataclass
class Replacement:
    entity_type: str
    source_codepoint_range: TextRange


@dataclass
class Result:
    text: str
    transformations: list[Located]


def test_escaped_quotes_map_to_original_source_and_replacement_is_quoted() -> None:
    source = '\ufeffnotes,keep\r\n"é before ""secret"" after",unchanged\r\n'

    def replace(text: str, start: int) -> CellResult:
        value = '"secret"'
        if value not in text[start:]:
            return Result(text, [])
        begin = text.index(value, start)
        return Result(
            text.replace(value, 'replacement,"value"'),
            [Replacement("TEST", TextRange(begin, begin + len(value)))],
        )

    result = process_csv(source, replace)
    item = result.transformations[0]
    assert (
        source[item.source_codepoint_range.start : item.source_codepoint_range.end] == '""secret""'
    )
    assert read_rows(result.text)[1] == ['é before replacement,"value" after', "unchanged"]


def test_headers_provide_npi_context_but_are_not_transformed() -> None:
    source = "NPI,US_ROUTING_NUMBER\n1234567893,021000021\n"
    result = process_csv(source, core_processor())
    assert read_rows(result.text)[0] == ["NPI", "US_ROUTING_NUMBER"]
    assert any(item.entity_type == "NPI" for item in result.transformations)
    # Canonical natural-language routing label is recognized by Core.
    routing = process_csv("routing number\n021000021\n", core_processor())
    assert any(item.entity_type == "US_ROUTING_NUMBER" for item in routing.transformations)


def test_headerless_empty_cells_and_remove_one_column_record() -> None:
    result = process_csv("a@example.com\r\n", core_processor("remove"), has_header=False)
    assert read_rows(result.text) == [[""]]
    assert result.transformations[0].record == 1
    unchanged = "a,,c\n,,\n"
    result = process_csv(unchanged, core_processor(), has_header=False)
    assert result.text == unchanged


@pytest.mark.parametrize(
    "source",
    [
        'a\n"unterminated',
        'a\n"closed"junk\n',
        "a\n\nvalue\n",
    ],
)
def test_malformed_csv_refused_without_echo(source: str) -> None:
    with pytest.raises(CsvError) as exc:
        process_csv(source, core_processor())
    assert source not in str(exc.value)
    assert "Malformed CSV" in str(exc.value)


def test_empty_header_only_and_tab_delimiter() -> None:
    for source in ("", "\ufeff", "a,b\r\n"):
        result = process_csv(source, core_processor())
        assert result.text == source
        assert result.transformations == []
    result = process_csv("email\tother\nfoo@example.com\tx\n", core_processor(), delimiter="\t")
    assert result.transformations[0].column == 1
    assert result.text == 'email\tother\n"[EMAIL]"\tx\n'
    with pytest.raises(CsvError, match="delimiter"):
        process_csv("a;b", core_processor(), delimiter=";")


def test_header_findings_excluded_and_bad_callback_rejected() -> None:
    source = "test@example.com\nvalue\n"
    assert process_csv(source, core_processor()).transformations == []

    def invalid(text: str, start: int) -> CellResult:
        return Result(text, [Replacement("EMAIL", TextRange(0, start + 1))])

    with pytest.raises(CsvError, match="boundary"):
        process_csv(source, invalid)

    def corrupt(text: str, start: int) -> CellResult:
        return Result("broken", [])

    with pytest.raises(CsvError, match="context"):
        process_csv(source, corrupt)
