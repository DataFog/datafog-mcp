"""
What stays in a copy in front of an email address, through the real MCP tools.

datafog-mcp 1.0.0 (datafog-core 0.4.4) matched an address together with the
text joined to its front, so a redacted copy lost that text too. Under core
1.7 the address alone is matched, and what stood in front of it stays unless
its own detector matches. These tests pin the examples the changelog gives
for that: query strings, pipe-delimited records, and local parts that begin
with a number shaped like another entity type.

All values are synthetic: reserved example domains, documentation IP ranges,
555-01xx numbers, and a JWT whose signature is the text "signature-synthetic".
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from datafog_mcp.server import mcp

ALICE = "alice@example.com"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkV4YW1wbGUifQ"
    ".c2lnbmF0dXJlLXN5bnRoZXRpYy1vbmx5LTAwMDAwMDAwMDA"
)

# Shapes that are split off the front of a local part, with the marker the
# default entity types leave in their place. PHONE, IP_ADDRESS, DATE and
# ZIP_CODE are opt-in, so by default those prefixes stay as written.
OPT_IN_SHAPES = {
    "2025550143": "PHONE",
    "+12025550143": "PHONE",
    "202-555-0143": "PHONE",
    "202.555.0143": "PHONE",
    "192.0.2.1": "IP_ADDRESS",
    "2001:db8::1": "IP_ADDRESS",
    "2026-10-01": "DATE",
    "10/01/2026": "DATE",
    "12345": "ZIP_CODE",
    "12345-6789": "ZIP_CODE",
}
DEFAULT_SHAPES = {
    "123-45-6789": "SSN",
    "123456789": "SSN",
    "4111111111111111": "CREDIT_CARD",
}
SEPARATORS = [".", "-", "_", "+", "'", "#", "/", "=", "?", "|", "&"]
# Digit runs that are no other type's shape: the address keeps them.
UNSPLIT_PREFIXES = ["1234.", "123456.", "20261001.", "123456789012.", "12345-", "2025550143!"]
EVERY_TYPE = ["EMAIL", "SSN", "CREDIT_CARD", "PHONE", "IP_ADDRESS", "DATE", "ZIP_CODE"]


def call(tool: str, path: Path, **arguments: Any) -> dict[str, Any]:
    """Invoke the real server through an in-memory MCP client."""

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, {"path": str(path), **arguments})
            assert not result.is_error
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


def redact(
    tmp_path: Path, filename: str, source: str, **arguments: Any
) -> tuple[str, dict[str, int]]:
    """
    Redact one synthetic file and return its copy and the reported counts.

    Parameters:
      tmp_path: The test's directory.
      filename: Decides the format: plain text, CSV cells, ENV or SQL.
      source: The file's content.
      arguments: Extra tool arguments, such as an explicit entity_types.

    Returns:
      The complete redacted copy, and the per-type counts.
    """
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8", newline="")
    result = call("datafog_redact", path, **arguments)
    assert ALICE not in json.dumps(result)
    with Path(result["output_path"]).open(encoding="utf-8", newline="") as handle:
        return handle.read(), result["counts"]


def in_format(extension: str, value: str) -> tuple[str, str, str]:
    """
    Place a value in a file of one format.

    Parameters:
      extension: txt, csv, env or sql.
      value: The text to place. For csv it must need no quoting.

    Returns:
      The filename, the file content, and the copy's layout with ``{}`` where
      the transformed value goes. A CSV copy quotes the changed cell.
    """
    layouts = {
        "txt": ("notes.txt", "{}\n", "{}\n"),
        "csv": ("notes.csv", "id,note\n7,{}\n", 'id,note\n7,"{}"\n'),
        "env": ("app.env", "KEY={}\n", "KEY={}\n"),
        "sql": ("rows.sql", "INSERT INTO t VALUES ('{}');\n", "INSERT INTO t VALUES ('{}');\n"),
    }
    filename, source, copy = layouts[extension]
    return filename, source.format(value), copy


# The changelog's query-string and delimited-record examples. 1.0.0 wrote
# "[EMAIL]" for each of the first and third lines, and "https:[EMAIL]" for
# the URL, removing everything joined to the front of the address.
@pytest.mark.parametrize(
    ("filename", "source", "copy"),
    [
        (
            "query.txt",
            f"user=alice&pass=hunter2&email={ALICE}\n",
            "user=alice&pass=hunter2&email=[EMAIL]\n",
        ),
        (
            "callback.txt",
            f"https://app.example.org/cb?id_token={JWT}&email={ALICE}\n",
            f"https://app.example.org/cb?id_token={JWT}&email=[EMAIL]\n",
        ),
        ("record.txt", f"1|Alice|Smith|{ALICE}\n", "1|Alice|Smith|[EMAIL]\n"),
        (
            "query.csv",
            f"id,note\n7,user=alice&pass=hunter2&email={ALICE}\n",
            'id,note\n7,"user=alice&pass=hunter2&email=[EMAIL]"\n',
        ),
        (
            "record.csv",
            f"id,note\n7,1|Alice|Smith|{ALICE}\n",
            'id,note\n7,"1|Alice|Smith|[EMAIL]"\n',
        ),
    ],
)
def test_text_before_an_address_stays_in_the_copy(
    tmp_path: Path, filename: str, source: str, copy: str
) -> None:
    """Only the address is replaced; a password, token or name before it is not."""
    copied, counts = redact(tmp_path, filename, source)

    assert copied == copy
    assert counts == {"EMAIL": 1}


def test_a_jwt_directly_after_an_equals_sign_is_not_detected(tmp_path: Path) -> None:
    """The token in the URL example has no detection of its own to remove it."""
    copied, counts = redact(tmp_path, "token.txt", f"id_token={JWT}\n")

    assert copied == f"id_token={JWT}\n"
    assert counts == {}

    copied, counts = redact(tmp_path, "spaced.txt", f"id_token {JWT}\n")

    assert copied == "id_token [JWT]\n"
    assert counts == {"JWT": 1}


def test_a_detected_value_before_an_address_is_still_replaced(tmp_path: Path) -> None:
    """Text in front of the address goes when a selected detector matches it."""
    copied, counts = redact(tmp_path, "query.txt", f"ssn=123-45-6789&email={ALICE}\n")

    assert copied == "ssn=[SSN]&email=[EMAIL]\n"
    assert counts == {"SSN": 1, "EMAIL": 1}


@pytest.mark.parametrize(
    ("filename", "source", "copy"),
    [
        ("app.env", f"URL=user=alice&pass=hunter2&email={ALICE}\n", "URL=[EMAIL]\n"),
        (
            "rows.sql",
            f"INSERT INTO t VALUES ('user=alice&pass=hunter2&email={ALICE}');\n",
            "INSERT INTO t VALUES ('[EMAIL]');\n",
        ),
    ],
)
def test_env_and_sql_values_keep_their_boundaries(
    tmp_path: Path, filename: str, source: str, copy: str
) -> None:
    """An ENV value or SQL string is still matched and replaced as a whole."""
    copied, counts = redact(tmp_path, filename, source)

    assert copied == copy
    assert counts == {"EMAIL": 1}


@pytest.mark.parametrize("extension", ["txt", "csv", "env", "sql"])
@pytest.mark.parametrize("separator", SEPARATORS)
@pytest.mark.parametrize("shape", list(OPT_IN_SHAPES))
def test_an_opt_in_shaped_prefix_stays_visible_by_default(
    tmp_path: Path, shape: str, separator: str, extension: str
) -> None:
    """A phone-, IP-, date- or ZIP-shaped prefix is split off and left as written."""
    if (shape, separator) == ("12345", "-"):
        pytest.skip("a five-digit number and a hyphen stay in the address; pinned below")
    prefix = shape + separator
    filename, source, copy = in_format(extension, prefix + ALICE)

    copied, counts = redact(tmp_path, filename, source)

    assert copied == copy.format(prefix + "[EMAIL]")
    assert counts == {"EMAIL": 1}


@pytest.mark.parametrize("extension", ["txt", "csv", "env", "sql"])
@pytest.mark.parametrize("separator", SEPARATORS)
@pytest.mark.parametrize("shape", list(DEFAULT_SHAPES))
def test_a_default_type_prefix_is_replaced_as_its_own_type(
    tmp_path: Path, shape: str, separator: str, extension: str
) -> None:
    """An SSN- or card-shaped prefix is split off and replaced by its own marker."""
    entity = DEFAULT_SHAPES[shape]
    filename, source, copy = in_format(extension, shape + separator + ALICE)

    copied, counts = redact(tmp_path, filename, source)

    assert copied == copy.format(f"[{entity}]{separator}[EMAIL]")
    assert counts == {entity: 1, "EMAIL": 1}


@pytest.mark.parametrize("separator", [".", "_", "+"])
@pytest.mark.parametrize("shape", list(OPT_IN_SHAPES))
def test_a_selected_opt_in_type_replaces_the_prefix(
    tmp_path: Path, shape: str, separator: str
) -> None:
    """With its type selected, the split-off prefix is replaced too."""
    entity = OPT_IN_SHAPES[shape]

    copied, counts = redact(
        tmp_path, "notes.txt", f"{shape}{separator}{ALICE}\n", entity_types=EVERY_TYPE
    )

    assert copied == f"[{entity}]{separator}[EMAIL]\n"
    assert counts == {entity: 1, "EMAIL": 1}


@pytest.mark.parametrize("extension", ["txt", "csv", "env", "sql"])
@pytest.mark.parametrize("prefix", UNSPLIT_PREFIXES)
def test_other_digit_runs_stay_in_the_address(tmp_path: Path, prefix: str, extension: str) -> None:
    """Digits that are no other type's shape are part of the local part."""
    filename, source, copy = in_format(extension, prefix + ALICE)

    copied, counts = redact(tmp_path, filename, source, entity_types=EVERY_TYPE)

    assert copied == copy.format("[EMAIL]")
    assert counts == {"EMAIL": 1}


@pytest.mark.parametrize(
    "local", ["2025550143", "12345", "192.0.2.1", "2026-10-01", "123-45-6789", "20261001"]
)
def test_an_all_digit_local_part_is_one_address(tmp_path: Path, local: str) -> None:
    """A number directly before the at sign is the local part, whatever its shape."""
    copied, counts = redact(tmp_path, "notes.txt", f"{local}@example.com\n")

    assert copied == "[EMAIL]\n"
    assert counts == {"EMAIL": 1}
