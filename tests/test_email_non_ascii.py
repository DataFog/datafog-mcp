"""
Email addresses next to non-ASCII letters, through the real MCP tools.

Known issue, tracked as https://github.com/DataFog/datafog-core/issues/272:
datafog-core 1.7.0 treats a non-ASCII letter that directly touches an email
address as part of the address. The changelog and docs/detection.md describe
the consequences, and this module backs them in two ways.

The first group pins what 1.7.0 does, exactly as documented: every example
in the known-issue entry, the characters that are affected and the ones that
are not, and the addresses that are found because of the same matching.
These run only on core 1.7.0, the release the documentation describes. On
another core release they are skipped, so a patch that fixes the issue does
not turn the suite red; the documentation must then be checked by hand.

The second group states the correct outcome and is a non-strict expected
failure: it fails today, and when a core release fixes the issue it passes
without failing the suite.

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

ISSUE = "https://github.com/DataFog/datafog-core/issues/272"
ALL_TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove"]

ALICE = "alice@example.com"
BOB = "bob@example.net"
SSN = "123-45-6789"
CARD = "4111 1111 1111 1111"

pins_core_1_7_0 = pytest.mark.skipif(
    Version(version("datafog-core")).release != (1, 7, 0),
    reason=f"pins the known issue as documented for datafog-core 1.7.0 ({ISSUE})",
)
correct_outcome = pytest.mark.xfail(
    reason=f"known issue: a non-ASCII letter touching an email address joins it ({ISSUE})",
    raises=(AssertionError, ToolError),
    strict=False,
)

# Letters that are taken into the address: accented Latin, Cyrillic, Chinese,
# Japanese and Korean, a combining accent, and a letter followed by a dot.
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


# ---------------------------------------------------------------------------
# What core 1.7.0 does, as the changelog and docs/detection.md describe it.
# ---------------------------------------------------------------------------


@pins_core_1_7_0
@pytest.mark.parametrize("layout", list(LAYOUTS))
@pytest.mark.parametrize("joiner", list(AFFECTED))
def test_known_issue_second_domain_stays_after_an_affected_letter(
    joiner: str, layout: str, tmp_path: Path
) -> None:
    """Two addresses joined by a letter are one match; the second domain is left."""
    filename, source, copy = LAYOUTS[layout]

    copied, counts = redact(tmp_path, filename, source.format(f"{ALICE}{AFFECTED[joiner]}{BOB}"))

    assert copied == copy.format("[EMAIL]@example.net")
    assert counts == {"EMAIL": 1}


@pins_core_1_7_0
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


@pins_core_1_7_0
@pytest.mark.parametrize("layout", list(LAYOUTS))
@pytest.mark.parametrize(
    "sentence",
    [f"メールは{ALICE}です", f"SSNは{SSN}でメールは{ALICE}です"],
    ids=["address-only", "with-ssn"],
)
def test_known_issue_unspaced_sentence_is_replaced_whole(
    sentence: str, layout: str, tmp_path: Path
) -> None:
    """The whole sentence becomes one EMAIL; an SSN inside it is not reported."""
    filename, source, copy = LAYOUTS[layout]

    copied, counts = redact(tmp_path, filename, source.format(sentence))

    assert copied == copy.format("[EMAIL]")
    assert counts == {"EMAIL": 1}


@pins_core_1_7_0
def test_known_issue_scan_reports_no_ssn_in_the_unspaced_sentence(tmp_path: Path) -> None:
    """The scan counts one EMAIL spanning the sentence and no SSN."""
    sentence = f"SSNは{SSN}でメールは{ALICE}です"
    path = write(tmp_path, "notes.txt", sentence + "\n")

    result = call("datafog_scan", path)

    assert result["counts"] == {"EMAIL": 1}
    assert [(item["type"], item["start"], item["end"]) for item in result["findings"]] == [
        ("EMAIL", 0, len(sentence))
    ]


@pins_core_1_7_0
@pytest.mark.parametrize("tool", ALL_TOOLS)
@pytest.mark.parametrize("layout", list(LAYOUTS))
def test_known_issue_spaced_card_before_such_text_is_refused(
    layout: str, tool: str, tmp_path: Path
) -> None:
    """Scans and writes refuse with the partial-overlap error and write nothing."""
    filename, source, _ = LAYOUTS[layout]
    path = write(tmp_path, filename, source.format(f"カードは{CARD}でメールは{ALICE}です"))

    with pytest.raises(ToolError) as refused:
        call(tool, path)

    message = str(refused.value)
    assert "partly overlap (CREDIT_CARD, EMAIL)" in message
    for fragment in ("4111", "1111", "alice", "example.com", "カード", "メール"):
        assert fragment not in message
    assert sorted(item.name for item in tmp_path.iterdir()) == [filename]


@pins_core_1_7_0
def test_a_separator_avoids_the_known_issue(tmp_path: Path) -> None:
    """With spaces between the values, each is found under its own type."""
    copied, counts = redact(tmp_path, "notes.txt", f"SSN {SSN} メール {ALICE} です\n")

    assert copied == "SSN [SSN] メール [EMAIL] です\n"
    assert counts == {"SSN": 1, "EMAIL": 1}


# The gain from the same matching. Version 1.0.0 found none of these, and a
# fix for the known issue must keep them, so they run on every core release.
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


# ---------------------------------------------------------------------------
# The correct outcome. Expected to fail until datafog-core fixes the issue;
# not strict, so a fixed core passes here without failing the suite.
# ---------------------------------------------------------------------------


def assert_values_are_covered(
    tool: str, tmp_path: Path, filename: str, source: str, values: tuple[str, ...]
) -> dict[str, int]:
    """
    Run one tool and require that it accounts for every character of the values.

    A scan must report spans that together cover each value completely. A
    write must produce a copy holding no value and no recognizable part of
    one. No response may contain a value. Exact copies are not asserted,
    because where a fixed core draws the boundary around an accented letter,
    which can itself begin a valid local part, is not yet known.

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


@correct_outcome
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


@correct_outcome
@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_ssn_and_address_in_an_unspaced_sentence_are_both_found(tool: str, tmp_path: Path) -> None:
    """The SSN is reported as an SSN, not lost inside the address match."""
    source = f"SSNは{SSN}でメールは{ALICE}です\n"

    counts = assert_values_are_covered(tool, tmp_path, "notes.txt", source, (SSN, ALICE))

    assert counts == {"SSN": 1, "EMAIL": 1}


@correct_outcome
@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_card_and_address_in_an_unspaced_sentence_are_processed(tool: str, tmp_path: Path) -> None:
    """The file is scanned and transformed, not refused for overlapping detections."""
    source = f"カードは{CARD}でメールは{ALICE}です\n"

    counts = assert_values_are_covered(tool, tmp_path, "notes.txt", source, (CARD, ALICE))

    assert counts == {"CREDIT_CARD": 1, "EMAIL": 1}
