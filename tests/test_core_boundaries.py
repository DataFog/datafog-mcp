"""
Values datafog-core 1.5.0 and 1.6.0 missed, through the real MCP tools.

Those two releases dropped an email address directly after closing
punctuation or dots, and a phone number directly after a digit and a comma or
at the end of a line whose successor starts with a digit. Core 1.7.0 finds
them again. Core 1.8 retains these fixes, and the server accepts 1.8.x only.
Every input here is asserted
exactly: the count, the reported span, and the complete copy each write tool
produces, so a core release that misses one of them again fails here.

All values are synthetic: reserved example domains and 555-01xx or Ofcom
drama-range numbers.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from packaging.requirements import Requirement
from packaging.version import Version

from datafog_mcp.server import mcp

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

ALL_TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]

ALICE = "alice@example.com"
CAROL = "carol@example.com"
US_PHONE = "+1-202-555-0143"
UK_PHONE = "+44 20 7946 0958"
FIRST_BARE = "2025550143"
SECOND_BARE = "2025550144"


@dataclass(frozen=True)
class Case:
    """
    One file, what a scan must report in it, and its redacted copy.

    Attributes:
      filename: Decides the format: plain text, CSV cells, ENV or SQL.
      source: The file's content.
      values: The matched values, in file order. The scan must report exactly
        these spans.
      redacted: The complete copy datafog_redact must write. The masked and
        removed copies are derived from it.
      entity: The one entity type the case is about.
      options: Extra tool arguments, such as an explicit entity_types.
      fragments: Parts of the values that no copy may contain.
    """

    filename: str
    source: str
    values: tuple[str, ...]
    redacted: str
    entity: str = "EMAIL"
    options: tuple[tuple[str, Any], ...] = ()
    fragments: tuple[str, ...] = ("alice", "carol", "example.com", "@")


PHONE_ONLY = (("entity_types", ["PHONE"]),)
PHONE_FRAGMENTS = ("202", "555", "0143", "0144", "7946", "0958", "+")

# The four inputs from the review that blocked the move to core 1.5.0 and
# 1.6.0, as plain text and as a CSV cell.
REVIEW_EMAIL_CASES = {
    "text-after-period-and-pipe": Case(
        "notes.txt",
        f"7|Reach {CAROL}.|{ALICE}\n",
        (CAROL, ALICE),
        "7|Reach [EMAIL].|[EMAIL]\n",
    ),
    "text-after-closing-quote-and-period": Case(
        "notes.txt",
        f'He wrote "see attached".{ALICE} replied\n',
        (ALICE,),
        'He wrote "see attached".[EMAIL] replied\n',
    ),
    "text-after-address-period-and-ampersand": Case(
        "notes.txt",
        f"{CAROL}.x&{ALICE}\n",
        (CAROL, ALICE),
        "[EMAIL].x&[EMAIL]\n",
    ),
    "text-after-short-quote-and-period": Case(
        "notes.txt",
        f'said "ok".{ALICE}\n',
        (ALICE,),
        'said "ok".[EMAIL]\n',
    ),
    "cell-after-period-and-pipe": Case(
        "notes.csv",
        f"id,note\n7,7|Reach {CAROL}.|{ALICE}\n",
        (CAROL, ALICE),
        'id,note\n7,"7|Reach [EMAIL].|[EMAIL]"\n',
    ),
    "cell-after-closing-quote-and-period": Case(
        "notes.csv",
        f'id,note\n7,"He wrote ""see attached"".{ALICE} replied"\n',
        (ALICE,),
        'id,note\n7,"He wrote ""see attached"".[EMAIL] replied"\n',
    ),
    "cell-after-address-period-and-ampersand": Case(
        "notes.csv",
        f"id,note\n7,{CAROL}.x&{ALICE}\n",
        (CAROL, ALICE),
        'id,note\n7,"[EMAIL].x&[EMAIL]"\n',
    ),
    "cell-after-short-quote-and-period": Case(
        "notes.csv",
        f'id,note\n7,"said ""ok"".{ALICE}"\n',
        (ALICE,),
        'id,note\n7,"said ""ok"".[EMAIL]"\n',
    ),
}

# An address directly after one or more dots, in every format that has its own
# email boundaries.
DOTTED_EMAIL_CASES = {
    "text-after-bracket-and-dot": Case(
        "notes.txt", f"see [1].{ALICE}\n", (ALICE,), "see [1].[EMAIL]\n"
    ),
    "text-after-three-dots": Case("notes.txt", f"me...{ALICE}\n", (ALICE,), "me...[EMAIL]\n"),
    "text-after-quote-and-dot": Case(
        "notes.txt", f'KEY=".{ALICE}"\n', (ALICE,), 'KEY=".[EMAIL]"\n'
    ),
    "cell-after-bracket-and-dot": Case(
        "notes.csv", f"id,note\n7,see [1].{ALICE}\n", (ALICE,), 'id,note\n7,"see [1].[EMAIL]"\n'
    ),
    "cell-after-three-dots": Case(
        "notes.csv", f"id,note\n7,me...{ALICE}\n", (ALICE,), 'id,note\n7,"me...[EMAIL]"\n'
    ),
    "cell-after-quote-and-dot": Case(
        "notes.csv",
        f'id,note\n7,"KEY="".{ALICE}"""\n',
        (ALICE,),
        'id,note\n7,"KEY="".[EMAIL]"""\n',
    ),
    "env-after-quote-and-dot": Case("app.env", f'KEY=".{ALICE}"\n', (ALICE,), 'KEY=".[EMAIL]"\n'),
    "env-after-three-dots": Case("app.env", f"KEY=me...{ALICE}\n", (ALICE,), "KEY=me...[EMAIL]\n"),
    "sql-after-quote-and-dot": Case(
        "rows.sql",
        f"INSERT INTO t VALUES ('.{ALICE}');\n",
        (ALICE,),
        "INSERT INTO t VALUES ('.[EMAIL]');\n",
    ),
    # The local part starts after the dots; the text before them is not part
    # of the address and stays in the copy.
    "text-two-dots-inside-a-word": Case(
        "notes.txt",
        "bob..x@example.com\n",
        ("x@example.com",),
        "bob..[EMAIL]\n",
        fragments=("x@", "example.com", "@"),
    ),
}

# PHONE is opt-in, so every case selects it explicitly.
PHONE_CASES = {
    "text-after-digit-and-comma": Case(
        "export.txt",
        f"2,{US_PHONE}\n",
        (US_PHONE,),
        "2,[PHONE]\n",
        "PHONE",
        PHONE_ONLY,
        PHONE_FRAGMENTS,
    ),
    # The first number ends a line and the next line starts with a digit.
    "text-rows-ending-before-a-digit": Case(
        "export.txt",
        f"id,phone\n1,{UK_PHONE}\n2,{UK_PHONE}\n",
        (UK_PHONE, UK_PHONE),
        "id,phone\n1,[PHONE]\n2,[PHONE]\n",
        "PHONE",
        PHONE_ONLY,
        PHONE_FRAGMENTS,
    ),
    # The same table under a CSV name, read as plain text on request.
    "csv-name-read-as-text": Case(
        "export.csv",
        f"id,phone\n1,{UK_PHONE}\n2,{UK_PHONE}\n",
        (UK_PHONE, UK_PHONE),
        "id,phone\n1,[PHONE]\n2,[PHONE]\n",
        "PHONE",
        (*PHONE_ONLY, ("input_format", "text")),
        PHONE_FRAGMENTS,
    ),
    "text-two-numbers-joined-by-a-comma": Case(
        "export.txt",
        f"{FIRST_BARE},{SECOND_BARE}\n",
        (FIRST_BARE, SECOND_BARE),
        "[PHONE],[PHONE]\n",
        "PHONE",
        PHONE_ONLY,
        PHONE_FRAGMENTS,
    ),
    "cell-after-a-numeric-column": Case(
        "export.csv",
        f"id,phone\n2,{US_PHONE}\n",
        (US_PHONE,),
        'id,phone\n2,"[PHONE]"\n',
        "PHONE",
        PHONE_ONLY,
        PHONE_FRAGMENTS,
    ),
    "cells-in-consecutive-rows": Case(
        "export.csv",
        f"id,phone\n1,{UK_PHONE}\n2,{UK_PHONE}\n",
        (UK_PHONE, UK_PHONE),
        'id,phone\n1,"[PHONE]"\n2,"[PHONE]"\n',
        "PHONE",
        PHONE_ONLY,
        PHONE_FRAGMENTS,
    ),
    "cells-in-adjacent-columns": Case(
        "export.csv",
        f"a,b\n{FIRST_BARE},{SECOND_BARE}\n",
        (FIRST_BARE, SECOND_BARE),
        'a,b\n"[PHONE]","[PHONE]"\n',
        "PHONE",
        PHONE_ONLY,
        PHONE_FRAGMENTS,
    ),
}

CASES = {**REVIEW_EMAIL_CASES, **DOTTED_EMAIL_CASES, **PHONE_CASES}


def call(tool: str, path: Path, **arguments: Any) -> dict[str, Any]:
    """Invoke the real server through an in-memory MCP client."""

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, {"path": str(path), **arguments})
            assert not result.is_error
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


def expected_copy(case: Case, tool: str) -> str:
    """
    Derive the exact copy a write tool must produce from the redacted one.

    Masking writes one asterisk per character of the value and removal writes
    nothing, each where redaction writes the type marker.

    Parameters:
      case: The case, with its redacted copy and its values in file order.
      tool: The write tool.

    Returns:
      The complete expected copy.
    """
    marker = f"[{case.entity}]"
    pieces = case.redacted.split(marker)
    assert len(pieces) == len(case.values) + 1
    if tool == "datafog_redact":
        return case.redacted
    fill = [("*" * len(value) if tool == "datafog_mask" else "") for value in case.values]
    return "".join(piece + filler for piece, filler in zip(pieces, [*fill, ""], strict=True))


def declared_core_requirement() -> Requirement:
    """
    Read the datafog-core requirement pyproject.toml declares.

    A regex rather than tomllib, which Python 3.10 lacks.

    Returns:
      The parsed requirement, with its version specifiers.
    """
    declared = re.search(r'"(datafog-core[^"]*)"', PYPROJECT.read_text(encoding="utf-8"))
    assert declared, "pyproject.toml declares no datafog-core requirement"
    return Requirement(declared.group(1))


def test_installed_core_is_the_one_minor_the_server_accepts() -> None:
    """
    A resolution outside the accepted datafog-core minor is caught first.

    Each core minor can change what a scan finds, so the server accepts one
    minor at a time: pyproject.toml declares a floor and caps the range at
    the next minor. The accepted line is read from that declaration, so this
    test and the dependency cannot disagree. Any release of the line passes,
    including a patch, pre-, post- or development release above the floor.
    """
    specifiers = {
        item.operator: Version(item.version) for item in declared_core_requirement().specifier
    }
    assert set(specifiers) == {">=", "<"}, "expected a floor and an upper cap"
    floor, cap = specifiers[">="], specifiers["<"]
    major, minor = floor.release[:2]
    assert cap.release == (major, minor + 1), "the cap must be the next minor"
    # Core 1.8 was reviewed against these previously fixed boundary cases.
    assert (major, minor) == (1, 8)

    installed = Version(version("datafog-core"))
    assert installed.release[:2] == (major, minor), installed
    assert declared_core_requirement().specifier.contains(installed, prereleases=True), installed


@pytest.mark.parametrize(
    ("candidate", "accepted"),
    [
        ("1.8.0", True),
        ("1.8.1", True),
        ("1.8.12", True),
        ("1.8.1rc1", True),
        ("1.8.1.dev3", True),
        ("1.8.0.post1", True),
        ("1.8.2+local.1", True),
        ("1.8.0rc1", False),
        ("1.7.9", False),
        ("1.9.0", False),
        ("1.9.0.dev1", False),
        ("1.9.0rc1", False),
        ("2.0.0", False),
    ],
)
def test_declared_range_admits_the_whole_1_8_line_and_nothing_else(
    candidate: str, accepted: bool
) -> None:
    """Patch, pre-, post- and development releases of 1.8 above the floor are in range."""
    specifier = declared_core_requirement().specifier

    assert specifier.contains(Version(candidate), prereleases=True) is accepted


@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize("name", list(CASES))
def test_values_core_1_5_and_1_6_missed_are_found(tool: str, name: str, tmp_path: Path) -> None:
    """Each value is counted once, located exactly, and absent from every copy."""
    case = CASES[name]
    source = tmp_path / case.filename
    source.write_text(case.source, encoding="utf-8", newline="")

    result = call(tool, source, **dict(case.options))

    assert result["counts"] == {case.entity: len(case.values)}
    assert result["entity_count"] == len(case.values)
    response = json.dumps(result)
    for value in case.values:
        assert value not in response

    if tool == "datafog_scan":
        assert result["findings_listed"] is True
        found = sorted(result["findings"], key=lambda item: item["start"])
        assert [item["type"] for item in found] == [case.entity] * len(case.values)
        assert [case.source[item["start"] : item["end"]] for item in found] == list(case.values)
        assert sorted(path.name for path in tmp_path.iterdir()) == [case.filename]
    else:
        with Path(result["output_path"]).open(encoding="utf-8", newline="") as handle:
            copied = handle.read()
        assert copied == expected_copy(case, tool)
        for fragment in case.fragments:
            assert fragment not in copied
    assert source.read_text(encoding="utf-8") == case.source


@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize(
    ("text", "values"),
    [
        # After a digit and a period, a number with a sign, parentheses or
        # another separator is a phone number.
        ("7.+1-202-555-0143\n", ["+1-202-555-0143"]),
        ("7.(202) 555-0143\n", ["(202) 555-0143"]),
        ("7.202-555-0143\n", ["202-555-0143"]),
        # An unseparated or dotted run there reads as the rest of a decimal or
        # a version, and is not reported.
        ("7.2025550143\n", []),
        ("7.202.555.0143\n", []),
        # After a digit and a comma, an unsigned single-dot decimal is not a
        # phone number; a signed one is.
        ("6,306.2723362\n", []),
        ("7,+1.2025550143\n", ["+1.2025550143"]),
        ("1,34,2025550143\n", ["2025550143"]),
    ],
)
def test_phone_boundaries_after_a_number(
    tool: str, text: str, values: list[str], tmp_path: Path
) -> None:
    """The changelog's phone boundaries hold for scans and for every copy."""
    source = tmp_path / "export.txt"
    source.write_text(text, encoding="utf-8")

    result = call(tool, source, entity_types=["PHONE"])

    assert result["counts"] == ({"PHONE": len(values)} if values else {})
    assert result["entity_count"] == len(values)
    if tool == "datafog_scan":
        assert [text[item["start"] : item["end"]] for item in result["findings"]] == values
    else:
        copied = Path(result["output_path"]).read_text(encoding="utf-8")
        for value in values:
            assert value not in copied
        if not values:
            assert copied == text


@pytest.mark.parametrize("separator", ["\x0b", "\x0c", "\x85", " ", " "])
def test_digit_groups_on_different_lines_are_not_one_phone_number(
    separator: str, tmp_path: Path
) -> None:
    """Phone numbers are matched per line, for every line separator."""
    source = tmp_path / "export.txt"
    source.write_text(f"202 555{separator}0143\n", encoding="utf-8", newline="")

    result = call("datafog_scan", source, entity_types=["PHONE"])

    assert result["entity_count"] == 0
    assert result["counts"] == {}
