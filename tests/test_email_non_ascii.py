"""
Email addresses next to non-ASCII letters, through the real MCP tools.

datafog-core 1.7.0 mishandles an address that touches a non-ASCII letter.
Two addresses joined by one, such as a Japanese particle, are reported as a
single match that ends inside the second address, so the copy keeps its
domain. An SSN or card number in the same unspaced sentence is swallowed by
the address match, or the file is refused for overlapping detections. The
fix belongs to datafog-core and is planned for 1.7.1.

This module states the outcome a correct engine must give, and nothing about
how 1.7.0 gets it wrong. Each test marked with ``fixed_in_1_7_1`` is a strict
expected failure while the installed core is older than 1.7.1, and an
ordinary test from 1.7.1 on. So the suite is green on 1.7.0, goes red if
1.7.0 unexpectedly passes one, and goes red if 1.7.1 does not fix them all.
The dependency floor is not changed here.

The assertions are deliberately the minimum that "correct" implies: no part
of any address, SSN or card number survives in a copy, and scan spans cover
every character of them. Exact copies and counts for the joined-address
cases depend on where 1.7.1 draws the boundary around an accented letter,
which can itself begin a valid local part, and should be pinned once it is
released.

The last tests are not expected failures: an address whose local part is
itself non-ASCII is covered completely by 1.7.0 and must stay so.

All values are synthetic: reserved example domains, a test card number and
an SSN-shaped number.
"""

from __future__ import annotations

import asyncio
import json
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from packaging.version import Version

from datafog_mcp.server import mcp

ALL_TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]

ALICE = "alice@example.com"
BOB = "bob@example.net"
SSN = "123-45-6789"
CARD = "4111 1111 1111 1111"

# Compared by release number, so a 1.7.1 pre-release must already pass.
CORE_HAS_FIX = Version(version("datafog-core")).release >= (1, 7, 1)

fixed_in_1_7_1 = pytest.mark.xfail(
    condition=not CORE_HAS_FIX,
    reason="datafog-core older than 1.7.1 mishandles an email address next to a non-ASCII letter",
    raises=(AssertionError, ToolError),
    strict=True,
)

# What stands between two addresses: accented Latin letters, Cyrillic, Chinese,
# Japanese and Korean conjunctions, a combining accent, and a letter and a dot.
JOINERS = {
    "e-acute": "é",
    "a-grave": "à",
    "u-umlaut": "ü",
    "cyrillic-i": "и",
    "chinese-he": "和",
    "chinese-huo": "或",
    "japanese-to": "と",
    "korean-wa": "와",
    "combining-acute": "é",
    "e-acute-and-dot": "é.",
}

# One layout per format with its own email boundaries.
LAYOUTS = {
    "text": ("notes.txt", "{}\n"),
    "csv": ("notes.csv", "id,note\n7,{}\n"),
    "env": ("app.env", "KEY={}\n"),
    "sql": ("rows.sql", "INSERT INTO t VALUES ('{}');\n"),
}


def call(tool: str, path: Path, **arguments: Any) -> dict[str, Any]:
    """Invoke the real server through an in-memory MCP client."""

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, {"path": str(path), **arguments})
            assert not result.is_error
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


def assert_values_are_covered(
    tool: str, tmp_path: Path, filename: str, source: str, values: tuple[str, ...]
) -> dict[str, int]:
    """
    Run one tool and require that it accounts for every character of the values.

    A scan must report spans that together cover each value completely. A
    write must produce a copy holding no value and no recognizable part of
    one. No response may contain a value.

    Parameters:
      tool: The tool to call.
      tmp_path: The test's directory.
      filename: Decides the format: plain text, CSV cells, ENV or SQL.
      source: The file's content.
      values: The sensitive values in it.

    Returns:
      The per-type counts the tool reported.
    """
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8", newline="")

    result = call(tool, path)

    response = json.dumps(result, ensure_ascii=False)
    for value in values:
        assert value not in response
    if tool == "datafog_scan":
        assert result["findings_listed"] is True
        covered = set()
        for finding in result["findings"]:
            covered.update(range(finding["start"], finding["end"]))
        for value in values:
            start = source.index(value)
            missing = set(range(start, start + len(value))) - covered
            assert not missing, f"{len(missing)} characters of a value are in no finding"
    else:
        with Path(result["output_path"]).open(encoding="utf-8", newline="") as handle:
            copied = handle.read()
        for value in values:
            assert value not in copied
            for part in value.replace("@", " @ ").replace(".", " ").replace("-", " ").split():
                if len(part) > 1 or part == "@":
                    assert part not in copied, "part of a value is still in the copy"
    assert path.read_text(encoding="utf-8") == source
    counts: dict[str, int] = result["counts"]
    return counts


@fixed_in_1_7_1
@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize("layout", list(LAYOUTS))
@pytest.mark.parametrize("joiner", list(JOINERS))
def test_two_addresses_joined_by_a_non_ascii_letter_are_both_covered(
    joiner: str, layout: str, tool: str, tmp_path: Path
) -> None:
    """Neither address leaves its name or its domain behind, in any format."""
    filename, template = LAYOUTS[layout]
    source = template.format(f"{ALICE}{JOINERS[joiner]}{BOB}")

    counts = assert_values_are_covered(tool, tmp_path, filename, source, (ALICE, BOB))

    assert set(counts) == {"EMAIL"}
    assert 1 <= counts["EMAIL"] <= 2


@fixed_in_1_7_1
@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_ssn_and_address_in_an_unspaced_sentence_are_both_found(tool: str, tmp_path: Path) -> None:
    """The SSN is reported as an SSN, not lost inside the address match."""
    source = f"SSNは{SSN}でメールは{ALICE}です\n"

    counts = assert_values_are_covered(tool, tmp_path, "notes.txt", source, (SSN, ALICE))

    assert counts == {"SSN": 1, "EMAIL": 1}


@fixed_in_1_7_1
@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_card_and_address_in_an_unspaced_sentence_are_processed(tool: str, tmp_path: Path) -> None:
    """The file is scanned and transformed, not refused for overlapping detections."""
    source = f"カードは{CARD}でメールは{ALICE}です\n"

    counts = assert_values_are_covered(tool, tmp_path, "notes.txt", source, (CARD, ALICE))

    assert counts == {"CREDIT_CARD": 1, "EMAIL": 1}


# Not expected failures: these hold on core 1.7.0 and must keep holding.
@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize("address", ["josé@example.com", "名前@example.com"])
@pytest.mark.parametrize("template", ["{}\n", "contact {} now\n", "連絡先 {} まで\n"])
def test_a_non_ascii_local_part_is_covered_whole(
    template: str, address: str, tool: str, tmp_path: Path
) -> None:
    """An internationalized local part is part of the address, from its first letter."""
    source = template.format(address)

    counts = assert_values_are_covered(tool, tmp_path, "notes.txt", source, (address,))

    assert counts == {"EMAIL": 1}
    if tool == "datafog_redact":
        copied = next(p for p in tmp_path.iterdir() if p.name != "notes.txt")
        assert copied.read_text(encoding="utf-8") == template.format("[EMAIL]")
