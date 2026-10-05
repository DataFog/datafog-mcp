"""Product contracts exercised through the actual MCP tool interface."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.paths import ALLOWED_ROOTS_VAR
from datafog_mcp.server import mcp


def call(tool: str, **arguments: Any) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool(tool, arguments)
            assert not result.is_error
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


def policy(body: str) -> Path:
    path = Path(os.environ["DATAFOG_POLICY_PATH"])
    path.write_text("version = 1\n" + body, encoding="utf-8")
    return path


@pytest.mark.parametrize("tool", ["datafog_redact", "datafog_mask", "datafog_remove"])
def test_allowlist_reload_is_consistent_across_scan_and_writes(tmp_path: Path, tool: str) -> None:
    original = "test@example.com Test@example.com jane@example.com\n"
    source = tmp_path / "contacts.txt"
    source.write_text(original)
    assert call("datafog_scan", path=str(source))["counts"] == {"EMAIL": 3}
    policy('[allow.exact]\nEMAIL = ["test@example.com"]\n')
    scanned = call("datafog_scan", path=str(source))
    checked = call("datafog_check_text", text=original)
    written = call(tool, path=str(source))
    assert scanned["counts"] == checked["counts"] == written["counts"] == {"EMAIL": 2}
    assert scanned["allowlist_applied"] is True
    output = Path(written["output_path"]).read_text()
    assert "test@example.com" in output
    assert "Test@example.com" not in output and "jane@example.com" not in output
    assert source.read_text() == original
    policy("[allow.exact]\nEMAIL = []\n")
    assert call("datafog_scan", path=str(source))["counts"] == {"EMAIL": 3}


def test_outbound_locations_privacy_defaults_and_limits() -> None:
    text = "é greeting\nContact jane@example.com on 2026-08-01, zip 94117."
    checked = call("datafog_check_text", text=text)
    assert checked["counts"] == {"EMAIL": 1}
    item = checked["findings"][0]
    assert text[item["start"] : item["end"]] == "jane@example.com"
    assert (item["line"], item["character_column"]) == (2, 9)
    assert "jane@example.com" not in json.dumps(checked)
    assert "greeting" not in json.dumps(checked)
    assert checked["advisory_action"] == "ask"
    policy("[limits]\nmax_text_bytes = 4\n")
    assert call("datafog_check_text", text="éé")["entity_count"] == 0
    with pytest.raises(ToolError, match="byte limit"):
        call("datafog_check_text", text="ééx")


@pytest.mark.parametrize("tool", ["datafog_redact", "datafog_mask", "datafog_remove"])
def test_csv_locations_and_preserved_structure(tmp_path: Path, tool: str) -> None:
    raw = '\ufeffname,email,note\r\nJosé,jane@example.com,"first\r\nsecond, ""quoted"""\r\n'
    source = tmp_path / "customers.csv"
    original = raw.encode()
    source.write_bytes(original)
    scanned = call("datafog_scan", path=str(source))
    assert scanned["counts"] == {"EMAIL": 1}
    finding = scanned["findings"][0]
    assert (finding["record"], finding["column"], finding["field_name"]) == (1, 2, "email")
    assert raw[finding["start"] : finding["end"]] == "jane@example.com"
    result = call(tool, path=str(source))
    transformed = Path(result["output_path"]).read_bytes().decode()
    rows = list(csv.reader(io.StringIO(transformed.lstrip("\ufeff"), newline="")))
    assert rows[0] == ["name", "email", "note"]
    assert len(rows) == 2 and len(rows[1]) == 3
    assert rows[1][0] == "José" and rows[1][2] == 'first\r\nsecond, "quoted"'
    assert source.read_bytes() == original
    assert result["counts"] == scanned["counts"]


def test_output_precedence_and_no_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("jane@example.com")
    configured, explicit = tmp_path / "configured", tmp_path / "explicit"
    configured.mkdir()
    explicit.mkdir()
    sibling = call("datafog_redact", path=str(source))
    assert Path(sibling["output_path"]).parent == tmp_path
    policy(f'[output]\ndirectory = "{configured}"\n')
    default = call("datafog_redact", path=str(source))
    assert Path(default["output_path"]).parent == configured
    destination = explicit / "chosen.txt"
    result = call("datafog_redact", path=str(source), output_path=str(destination))
    assert Path(result["output_path"]) == destination
    before = destination.read_bytes()
    with pytest.raises(ToolError, match="already exists"):
        call("datafog_redact", path=str(source), output_path=str(destination))
    assert destination.read_bytes() == before
    with pytest.raises(ToolError):
        call("datafog_redact", path=str(source), output_path=str(source))
    assert source.read_text() == "jane@example.com"


def test_output_directory_does_not_grant_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    source = allowed / "source.txt"
    source.write_text("jane@example.com")
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, str(allowed))
    policy(f'[output]\ndirectory = "{outside}"\n')
    with pytest.raises(ToolError, match="outside the allowed roots"):
        call("datafog_redact", path=str(source))
    assert not list(outside.iterdir())
    policy(f'[output]\ndirectory = "{allowed / "missing"}"\n')
    with pytest.raises(ToolError):
        call("datafog_redact", path=str(source))
    assert not (allowed / "missing").exists()


def test_batch_reports_failures_continues_and_recursion_is_opt_in(tmp_path: Path) -> None:
    folder = tmp_path / "batch"
    folder.mkdir()
    (folder / "contacts.txt").write_text("jane@example.com")
    (folder / "clean.txt").write_text("no identifiers")
    (folder / "unsupported.xlsx").write_bytes(b"PK\x03\x04\x00")
    nested = folder / "nested"
    nested.mkdir()
    (nested / "contacts.txt").write_text("other@example.com")
    before = sorted(str(p) for p in folder.rglob("*"))
    result = call("datafog_scan_batch", paths=[str(folder)])
    assert result["file_count"] == 3 and result["error_count"] == 1
    assert result["counts"] == {"EMAIL": 1}
    outcomes = {Path(item["path"]).name: item for item in result["files"]}
    assert outcomes["clean.txt"]["status"] == "success"
    assert outcomes["clean.txt"]["entity_count"] == 0
    assert outcomes["unsupported.xlsx"]["status"] == "error"
    recursive = call("datafog_scan_batch", paths=[str(folder)], recursive=True)
    assert recursive["file_count"] == 4 and recursive["counts"] == {"EMAIL": 2}
    assert before == sorted(str(p) for p in folder.rglob("*"))


def test_pagination_is_complete_and_rejects_stale_content_and_policy(tmp_path: Path) -> None:
    source = tmp_path / "many.txt"
    source.write_text("a@example.com b@example.com c@example.com")
    policy("[limits]\nmax_findings = 1\n")
    first = call("datafog_scan", path=str(source), limit=10)
    assert first["entity_count"] == 3 and len(first["findings"]) == 1
    assert first["complete"] is False and first["next_offset"] == 1
    collected = first["findings"][:]
    page = first
    while page["next_offset"] is not None:
        page = call(
            "datafog_scan",
            path=str(source),
            offset=page["next_offset"],
            content_digest=first["content_digest"],
        )
        collected.extend(page["findings"])
    assert len({(x["start"], x["end"]) for x in collected}) == 3
    assert page["complete"] is True
    with pytest.raises(ToolError, match="requires"):
        call("datafog_scan", path=str(source), offset=1)
    source.write_text(source.read_text() + " d@example.com")
    with pytest.raises(ToolError, match="changed"):
        call("datafog_scan", path=str(source), offset=1, content_digest=first["content_digest"])
    first = call("datafog_scan", path=str(source))
    policy('[allow.exact]\nEMAIL = ["a@example.com"]\n')
    with pytest.raises(ToolError, match="changed"):
        call("datafog_scan", path=str(source), offset=1, content_digest=first["content_digest"])


def test_policy_discovery_scope_reload_and_logs_are_metadata_only(tmp_path: Path) -> None:
    source = tmp_path / "jane_personal.txt"
    source.write_text("jane@example.com")
    log = tmp_path / "activity.jsonl"
    assert call("datafog_scan", path=str(source))["activity_log"] == "disabled"
    assert not log.exists()
    policy(f'''[scope]
folders = ["{tmp_path}"]
extensions = [".txt"]
[workflow]
on_findings = "stop"
[logging]
enabled = true
path = "{log}"
[allow.exact]
EMAIL = ["allowed-private@example.com"]
''')
    discover = call("datafog_get_policy")
    assert discover["on_findings"] == "stop"
    assert discover["scope"]["extensions"] == [".txt"]
    assert "allowed-private@example.com" not in json.dumps(discover)
    result = call("datafog_scan", path=str(source))
    assert result["within_scan_scope"] is True and result["advisory_action"] == "stop"
    assert result["activity_log"] == "recorded"
    with pytest.raises(ToolError):
        call("datafog_scan", path=str(tmp_path / "missing.txt"))
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    assert [x["outcome"] for x in lines] == ["success", "error"]
    assert lines[0]["counts"] == {"EMAIL": 1}
    assert all(set(x) == {"time", "operation", "outcome", "counts"} for x in lines)
    assert "jane" not in log.read_text() and str(tmp_path) not in log.read_text()


def test_unexpected_engine_failure_cannot_be_misreported_as_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datafog_mcp import server

    source = tmp_path / "clean.txt"
    source.write_text("anything")

    def broken(text: str, config: object = None) -> list[Any]:
        raise RuntimeError("private sentinel")

    monkeypatch.setattr(server, "scan", broken)
    with pytest.raises(ToolError, match="RuntimeError") as exc:
        call("datafog_scan", path=str(source))
    assert "private sentinel" not in str(exc.value)
    batch = call("datafog_scan_batch", paths=[str(source)])
    assert batch["error_count"] == 1
    assert batch["files"][0]["status"] == "error"


def test_malformed_policy_and_csv_fail_explicitly_without_writing(tmp_path: Path) -> None:
    source = tmp_path / "broken.csv"
    source.write_text("email,other\njane@example.com\n")
    with pytest.raises(ToolError, match="Malformed CSV"):
        call("datafog_redact", path=str(source))
    assert not source.with_name("broken_redacted.csv").exists()
    # A .csv extension can denote an intentionally non-tabular text export;
    # the explicit override is available, but never silently chosen on failure.
    assert call("datafog_scan", path=str(source), input_format="text")["counts"] == {"EMAIL": 1}
    policy('[allow.exact]\nEMAIL = ["secret@example.com"\n')
    with pytest.raises(ToolError) as exc:
        call("datafog_scan", path=str(source), input_format="text")
    assert "secret@example.com" not in str(exc.value)


def test_scope_is_advisory_and_does_not_disable_explicit_scanning(tmp_path: Path) -> None:
    source = tmp_path / "data.txt"
    source.write_text("a@example.com")
    policy('[scope]\nextensions = [".csv"]\n[workflow]\non_findings = "proceed"\n')
    result = call("datafog_scan", path=str(source))
    assert result["within_scan_scope"] is False
    assert result["counts"] == {"EMAIL": 1}
    assert result["advisory_action"] == "proceed"
    assert result["advisory_only"] is True
