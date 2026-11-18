"""Mixed-script email coverage through all four MCP tools.

Core 1.8 fixes the non-ASCII adjacency regression tracked in core issue #272.
These are enforced regressions: every planted address, SSN and card must be
covered, internationalized addresses stay whole, and responses expose no value.
All values are synthetic.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from datafog_mcp.server import mcp

ALL_TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]

ALICE = "alice@example.com"
BOB = "bob@example.net"
SSN = "123-45-6789"
CARD = "4111 1111 1111 1111"

# Joiners that previously swallowed the second address: accented Latin,
# Cyrillic, Han, Hiragana, Hangul, a combining accent and a letter plus dot.
AFFECTED = {
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
# Punctuation, spacing and emoji that are not: the addresses stay separate.
UNAFFECTED = {
    "ideographic-comma": "、",
    "ideographic-full-stop": "。",
    "fullwidth-colon": "：",
    "fullwidth-parenthesis": "（",
    "no-break-space": " ",
    "zero-width-space": "​",
    "emoji": "😀",
}

# One layout per format with its own email boundaries: the filename, the
# source around a value, and the copy around its replacement. A CSV copy
# quotes the changed cell.
LAYOUTS = {
    "text": ("notes.txt", "{}\n", "{}\n"),
    "csv": ("notes.csv", "id,note\n7,{}\n", 'id,note\n7,"{}"\n'),
    "env": ("app.env", "KEY={}\n", "KEY={}\n"),
    "sql": ("rows.sql", "INSERT INTO t VALUES ('{}');\n", "INSERT INTO t VALUES ('{}');\n"),
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


def write(tmp_path: Path, filename: str, source: str) -> Path:
    """Create one synthetic input file, keeping its line endings as written."""
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8", newline="")
    return path


def redact(tmp_path: Path, filename: str, source: str) -> tuple[str, dict[str, int]]:
    """
    Redact one synthetic file.

    Parameters:
      tmp_path: The test's directory.
      filename: Decides the format: plain text, CSV cells, ENV or SQL.
      source: The file's content.

    Returns:
      The complete redacted copy, and the per-type counts.
    """
    result = call("datafog_redact", write(tmp_path, filename, source))
    with Path(result["output_path"]).open(encoding="utf-8", newline="") as handle:
        return handle.read(), result["counts"]


@pytest.mark.parametrize("layout", list(LAYOUTS))
@pytest.mark.parametrize("joiner", list(UNAFFECTED))
def test_punctuation_spacing_and_emoji_keep_two_addresses_apart(
    joiner: str, layout: str, tmp_path: Path
) -> None:
    """Both addresses are found and the character between them is kept."""
    filename, source, copy = LAYOUTS[layout]
    between = UNAFFECTED[joiner]

    copied, counts = redact(tmp_path, filename, source.format(f"{ALICE}{between}{BOB}"))

    assert copied == copy.format(f"[EMAIL]{between}[EMAIL]")
    assert counts == {"EMAIL": 2}


# Internationalized local parts and domains keep their complete spans.
@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize(
    "address", ["josé@example.com", "名前@example.com", "alice@bücher.example"]
)
@pytest.mark.parametrize("template", ["{}\n", "contact {} now\n", "連絡先 {} まで\n"])
def test_an_address_with_non_ascii_letters_is_found_whole(
    template: str, address: str, tool: str, tmp_path: Path
) -> None:
    """An internationalized local part or domain is covered from end to end."""
    source = template.format(address)
    path = write(tmp_path, "notes.txt", source)

    result = call(tool, path)

    assert result["counts"] == {"EMAIL": 1}
    assert address not in json.dumps(result, ensure_ascii=False)
    if tool == "datafog_scan":
        start = source.index(address)
        assert [(item["start"], item["end"]) for item in result["findings"]] == [
            (start, start + len(address))
        ]
    else:
        fill = {"datafog_redact": "[EMAIL]", "datafog_mask": "*" * len(address)}.get(tool, "")
        copied = Path(result["output_path"]).read_text(encoding="utf-8")
        assert copied == template.format(fill)


def assert_values_are_covered(
    tool: str, tmp_path: Path, filename: str, source: str, values: tuple[str, ...]
) -> dict[str, int]:
    """
    Run one tool and require that it accounts for every character of the values.

    A scan must report spans that together cover each value completely. A
    write must produce a copy holding no value and no recognizable part of
    one. No response may contain a value. Exact copies are not asserted,
    because an accented letter can itself begin a valid local part; Core may
    include it in the second address rather than preserve it between markers.

    Parameters:
      tool: The tool to call.
      tmp_path: The test's directory.
      filename: Decides the format: plain text, CSV cells, ENV or SQL.
      source: The file's content.
      values: The sensitive values in it.

    Returns:
      The per-type counts the tool reported.
    """
    path = write(tmp_path, filename, source)

    result = call(tool, path)

    response = json.dumps(result, ensure_ascii=False)
    for value in values:
        assert value not in response
    if tool == "datafog_scan":
        assert result["findings_listed"] is True
        covered: set[int] = set()
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


@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize("layout", list(LAYOUTS))
@pytest.mark.parametrize("joiner", list(AFFECTED))
def test_two_addresses_joined_by_a_non_ascii_letter_are_both_covered(
    joiner: str, layout: str, tool: str, tmp_path: Path
) -> None:
    """Neither address leaves its name or its domain behind, in any format."""
    filename, source, _ = LAYOUTS[layout]

    counts = assert_values_are_covered(
        tool, tmp_path, filename, source.format(f"{ALICE}{AFFECTED[joiner]}{BOB}"), (ALICE, BOB)
    )

    assert set(counts) == {"EMAIL"}
    assert 1 <= counts["EMAIL"] <= 2


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_ssn_and_address_in_an_unspaced_sentence_are_both_found(tool: str, tmp_path: Path) -> None:
    """The SSN is reported as an SSN, not lost inside the address match."""
    source = f"SSNは{SSN}でメールは{ALICE}です\n"

    counts = assert_values_are_covered(tool, tmp_path, "notes.txt", source, (SSN, ALICE))

    assert counts == {"SSN": 1, "EMAIL": 1}


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_card_and_address_in_an_unspaced_sentence_are_processed(tool: str, tmp_path: Path) -> None:
    """The file is scanned and transformed, not refused for overlapping detections."""
    source = f"カードは{CARD}でメールは{ALICE}です\n"

    counts = assert_values_are_covered(tool, tmp_path, "notes.txt", source, (CARD, ALICE))

    assert counts == {"CREDIT_CARD": 1, "EMAIL": 1}
