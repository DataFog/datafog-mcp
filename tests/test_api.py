"""
The public Python interface: importable without the server, and private.

A hook process imports datafog_mcp.api on every tool call, so it must not pull
in the MCP server's dependencies, and nothing it returns or prints may carry
an approved allowlist value or a matched value.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from datafog_mcp import api, policy
from datafog_mcp.server import mcp

SRC = Path(__file__).resolve().parent.parent / "src"

# Synthetic values on reserved example domains.
APPROVED = "public-support@example.com"
PRIVATE = "private-person@example.com"
NPI = "1234567893"

# Run in a fresh interpreter: this test process has already imported fastmcp.
PROBE = """\
import json
import sys

import datafog_mcp.api as api

current = api.load_policy()
api.allowed_roots()
api.vault_configured()
result = api.process_text("email\\ncontact@example.com\\n", policy=current, source="rows.csv")
print(json.dumps({
    "count": len(result.transformations),
    "loaded": sorted(name for name in sys.modules if name.split(".")[0] in ("fastmcp", "mcp")),
}))
"""


def configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    """Point the policy loader at a version-1 policy with the given body."""
    location = tmp_path / "policy.toml"
    location.write_text("version = 1\n" + body, encoding="utf-8")
    monkeypatch.setattr(policy, "POLICY_FILE", location)
    return location


def test_importing_and_using_the_api_does_not_import_the_server(tmp_path: Path) -> None:
    """
    Neither fastmcp nor mcp is loaded by importing or exercising the interface.

    Checked after real calls, not only after the import, so a lazy import
    inside a function would be caught too.
    """
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(filter(None, [str(SRC), os.environ.get("PYTHONPATH")])),
        "HOME": str(tmp_path),
    }
    environment.pop("DATAFOG_VAULT_DIR", None)

    completed = subprocess.run(
        [sys.executable, "-c", PROBE],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"count": 1, "loaded": []}


def test_public_names_are_exactly_the_documented_ones() -> None:
    """Adding or dropping a public name is a deliberate, reviewed change."""
    assert sorted(api.__all__) == [
        "ALLOWED_ROOTS_VAR",
        "Action",
        "CellProcessor",
        "CellResult",
        "CsvError",
        "CsvFinding",
        "CsvResult",
        "DEFAULT_ENTITIES",
        "DEFAULT_MAX_BYTES",
        "DENIED_DIR_NAMES",
        "FileContent",
        "FileTooLarge",
        "InputFormat",
        "Located",
        "NotARegularFile",
        "NotText",
        "OverlapConflict",
        "PathNotAllowed",
        "PathNotFound",
        "Policy",
        "PolicyFileError",
        "ReadError",
        "RootPolicy",
        "RootPolicyError",
        "SUPPORTED_ENTITIES",
        "ScanConfig",
        "Strategy",
        "VAULT_DIR_VAR",
        "VaultConfigError",
        "allowed_roots",
        "counts_by_type",
        "load_policy",
        "process_csv",
        "process_text",
        "read_text_file",
        "resolve_input",
        "root_policy",
        "vault_configured",
        "vault_dir",
    ]
    for name in api.__all__:
        assert hasattr(api, name), name


def test_earlier_names_still_work_from_their_modules() -> None:
    """
    The names used before the interface was named are aliases, not copies.

    Internal code and existing tests keep using them; the public interface
    exports only the new ones.
    """
    from datafog_mcp import paths

    assert policy.OutputPolicy is api.Policy
    assert policy.load_output_policy is api.load_policy
    assert policy.OutputPolicyError is api.PolicyFileError
    assert paths.PolicyError is api.RootPolicyError
    assert not {"OutputPolicy", "load_output_policy", "OutputPolicyError", "PolicyError"} & set(
        api.__all__
    )


def test_no_public_name_writes_files() -> None:
    """The interface reads and scans; writing copies stays with the server."""
    assert not {"resolve_output", "write_text_file"} & set(dir(api))


def test_policy_text_forms_never_show_allowlist_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Logging a policy, or its allowlist mapping, prints counts only."""
    configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL = ["{APPROVED}", "second@example.com"]')

    current = api.load_policy()

    assert current.allowlist_counts == {"EMAIL": 2}
    assert current.is_allowlisted("EMAIL", APPROVED)
    assert not current.is_allowlisted("EMAIL", PRIVATE)
    assert not current.is_allowlisted("SSN", APPROVED)
    for rendered in (
        repr(current),
        str(current),
        f"{current}",
        repr(current.allow_exact),
        str(current.allow_exact),
        repr(current.allow_exact["EMAIL"]),
        str(dict(current.allow_exact)),
    ):
        assert APPROVED not in rendered
        assert "second@example.com" not in rendered
        assert "example.com" not in rendered


@pytest.mark.parametrize(
    "body",
    [
        f'[allow.exact]\nEMAIL = ["{APPROVED}", 5]',
        f'[allow.exact]\nEMAIL = ["{APPROVED}", ""]',
        f'[allow.exact]\nNOT_A_TYPE = ["{APPROVED}"]',
        f'[allow.exact]\nEMAIL = "{APPROVED}"',
        f'[allow]\nexact = ["{APPROVED}"]',
        f'[allow.exact]\nEMAIL = ["{APPROVED}"\n',
    ],
)
def test_policy_errors_never_show_allowlist_values(
    body: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rejected policy is described without quoting what it contained."""
    configure(tmp_path, monkeypatch, body)

    with pytest.raises(api.PolicyFileError) as refused:
        api.load_policy()

    assert APPROVED not in str(refused.value)
    assert APPROVED not in repr(refused.value)
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None or refused.value.__suppress_context__


def test_process_text_applies_allowlists_and_returns_no_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Results give types and positions; the approved value is left alone."""
    configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL = ["{APPROVED}"]')
    text = f"{APPROVED} and {PRIVATE}"

    result = api.process_text(text, policy=api.load_policy())

    assert result.text == f"{APPROVED} and [EMAIL]"
    assert api.counts_by_type(result.transformations) == {"EMAIL": 1}
    (found,) = result.transformations
    span = found.source_codepoint_range
    assert (found.entity_type, span.start, span.end) == ("EMAIL", text.index(PRIVATE), len(text))
    assert not hasattr(found, "matched_text")
    assert PRIVATE not in repr(result.transformations)


def test_process_text_scans_table_cells_with_header_context() -> None:
    """A table is read cell by cell, and its header labels the column."""
    text = f"NPI,email\r\n{NPI},{PRIVATE}\r\n"

    result = api.process_text(text, policy=api.Policy(), source="providers.csv")

    assert result.text == 'NPI,email\r\n"[NPI]","[EMAIL]"\r\n'
    located = [
        (item.entity_type, item.record, item.column)
        for item in result.transformations
        if isinstance(item, api.CsvFinding)
    ]
    assert located == [("NPI", 1, 1), ("EMAIL", 1, 2)]
    assert NPI not in repr(result.transformations)
    assert PRIVATE not in repr(result.transformations)
    # The same text as plain text has no header context, so the bare number
    # is not reported as an NPI.
    flat = api.process_text(text, policy=api.Policy(), source="providers.txt")
    assert api.counts_by_type(flat.transformations) == {"EMAIL": 1}


@pytest.mark.parametrize(
    ("filename", "options"),
    [
        ("rows.csv", {}),
        ("rows.csv", {"has_header": False}),
        ("rows.tsv", {}),
        ("rows.txt", {"input_format": "csv"}),
        ("notes.txt", {}),
        ("settings.env", {}),
        ("dump.sql", {}),
        ("rows.csv", {"entity_types": ["EMAIL", "PHONE"]}),
    ],
)
def test_process_text_agrees_with_the_scan_tool(
    filename: str, options: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An embedding program and the MCP tool report the same findings."""
    configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL = ["{APPROVED}"]')
    delimiter = "\t" if filename.endswith(".tsv") else ","
    text = (
        f"email{delimiter}phone\n"
        f"{PRIVATE}{delimiter}555-010-0199\n"
        f"{APPROVED}{delimiter}555-010-0123\n"
        f"EMAIL='{PRIVATE}'{delimiter}x\n"
    )
    source = tmp_path / filename
    source.write_text(text, encoding="utf-8")

    async def scan() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool("datafog_scan", {"path": str(source), **options})
            assert result.structured_content is not None
            return result.structured_content

    from_tool = asyncio.run(scan())
    entity_types = options.get("entity_types")
    direct = api.process_text(
        api.read_text_file(str(source), api.DEFAULT_MAX_BYTES).text,
        policy=api.load_policy(),
        source=source,
        config=api.ScanConfig(entities=tuple(entity_types)) if entity_types else None,
        input_format=options.get("input_format", "auto"),
        has_header=options.get("has_header", True),
    )

    assert from_tool["entity_count"] >= 1
    assert [
        (item.entity_type, item.source_codepoint_range.start, item.source_codepoint_range.end)
        for item in direct.transformations
    ] == [(item["type"], item["start"], item["end"]) for item in from_tool["findings"]]
    assert api.counts_by_type(direct.transformations) == from_tool["counts"]


def test_process_text_reports_overlaps_and_bad_tables_without_content() -> None:
    """The two errors written to be shown hold types and locations only."""
    card = "4111 1111 1111 1111"
    uri = "postgres://app:s3cretpw@db.example.com:5432/app"

    with pytest.raises(api.OverlapConflict) as overlap:
        api.process_text(f"{uri};{card}", policy=api.Policy())
    with pytest.raises(api.CsvError) as malformed:
        api.process_text(f'email\n"{PRIVATE}\n', policy=api.Policy(), source="rows.csv")

    assert "CREDENTIAL_URI, CREDIT_CARD" in str(overlap.value)
    assert card not in str(overlap.value)
    assert uri not in str(overlap.value)
    assert "s3cretpw" not in str(overlap.value)
    assert "record 2, column 1" in str(malformed.value)
    assert PRIVATE not in str(malformed.value)


@pytest.mark.parametrize("given", ["nope", "CSV", "", "private-person@example.com", None])
def test_process_text_refuses_an_unknown_input_format(given: Any) -> None:
    """An unknown format is an error, not a silent plain-text scan."""
    with pytest.raises(ValueError) as refused:
        api.process_text(PRIVATE, policy=api.Policy(), input_format=given)

    assert str(refused.value) == "input_format must be one of: auto, text, csv, tsv, env, sql"
    assert PRIVATE not in str(refused.value)


@pytest.mark.parametrize("given", ["shred", "REDACT", "", "private-person@example.com", None])
def test_process_text_refuses_an_unknown_strategy(given: Any) -> None:
    """An unknown strategy is a ValueError listing the choices, not a KeyError."""
    with pytest.raises(ValueError) as refused:
        api.process_text(PRIVATE, policy=api.Policy(), strategy=given)

    assert not isinstance(refused.value, KeyError)
    assert str(refused.value) == "strategy must be one of: mask, redact, remove"
    assert PRIVATE not in str(refused.value)


@pytest.mark.parametrize("input_format", ["auto", "text", "csv", "tsv", "env", "sql"])
@pytest.mark.parametrize("strategy", ["mask", "redact", "remove"])
def test_process_text_accepts_every_documented_format_and_strategy(
    input_format: api.InputFormat, strategy: api.Strategy
) -> None:
    """Validation refuses nothing the signature allows."""
    result = api.process_text(
        f"email\n{PRIVATE}\n", policy=api.Policy(), input_format=input_format, strategy=strategy
    )

    assert api.counts_by_type(result.transformations) == {"EMAIL": 1}
    assert PRIVATE not in result.text


def test_package_ships_a_type_marker() -> None:
    """py.typed tells type checkers to use the package's own annotations."""
    marker = Path(api.__file__).with_name("py.typed")

    assert marker.is_file()
    assert marker.read_bytes() == b""


def test_path_checks_match_the_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Roots and credential-directory refusals are the server's own."""
    allowed = tmp_path / "allowed"
    (allowed / ".ssh").mkdir(parents=True)
    inside = allowed / "export.csv"
    inside.write_text("email\n", encoding="utf-8")
    outside = tmp_path / "outside.csv"
    outside.write_text("email\n", encoding="utf-8")
    monkeypatch.setenv(api.ALLOWED_ROOTS_VAR, str(allowed))

    assert api.allowed_roots() == (allowed.resolve(),)
    assert api.root_policy().source == f"${api.ALLOWED_ROOTS_VAR}"
    assert api.resolve_input(str(inside)) == inside.resolve()
    assert api.read_text_file(str(inside), api.DEFAULT_MAX_BYTES).text == "email\n"
    with pytest.raises(api.PathNotAllowed, match="outside the allowed roots"):
        api.resolve_input(str(outside))
    with pytest.raises(api.PathNotAllowed, match="credential directory"):
        api.resolve_input(str(allowed / ".ssh" / "config"))
    with pytest.raises(api.PathNotFound):
        api.read_text_file(str(allowed / "absent.csv"), api.DEFAULT_MAX_BYTES)


def test_scope_and_workflow_are_readable_from_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hook can ask whether a path is in routine scope and what to do next."""
    exports = tmp_path / "exports"
    exports.mkdir()
    configure(
        tmp_path,
        monkeypatch,
        f'[scope]\nfolders = ["{exports.as_posix()}"]\nextensions = [".csv"]\n'
        '[workflow]\non_findings = "stop"\ntransform_strategy = "mask"',
    )

    current = api.load_policy()

    assert current.in_scope(exports.resolve() / "rows.CSV")
    assert not current.in_scope(exports.resolve() / "rows.txt")
    assert not current.in_scope(tmp_path.resolve() / "rows.csv")
    assert (current.on_findings, current.transform_strategy) == ("stop", "mask")
    assert current.warnings == []
