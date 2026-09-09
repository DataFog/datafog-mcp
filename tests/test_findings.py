"""Tests for datafog_mcp.findings."""

from __future__ import annotations

import pytest
from datafog_core import Finding, TextRange

from datafog_mcp.findings import (
    UnsupportedMode,
    counts_by_type,
    finding_to_dict,
    render,
    render_transformation,
)


def _finding(
    entity_type: str = "EMAIL",
    matched_text: str = "josh@example.com",
    start: int = 0,
    end: int = 16,
) -> Finding:
    """
    Build a detection record for testing.

    Parameters:
      entity_type: Detected entity type.
      matched_text: Matched substring.
      start: Start offset in the source text.
      end: End offset in the source text.
    Returns:
      A populated Finding.
    """
    return Finding(
        entity_type=entity_type,
        matched_text=matched_text,
        byte_range=TextRange(start, end),
        codepoint_range=TextRange(start, end),
        detector_name="datafog-core/test",
    )


def test_finding_to_dict_omits_the_matched_value() -> None:
    """
    The record locates a finding without disclosing it.

    Returning matched_text would put into context exactly what
    path-based scanning exists to keep out.
    """
    record = finding_to_dict(_finding())

    assert record == {"type": "EMAIL", "start": 0, "end": 16}
    assert "josh@example.com" not in str(record)


def test_counts_by_type_tallies() -> None:
    """Repeated types accumulate; distinct types stay separate."""
    findings = [_finding(), _finding(), _finding("DATE", "03/14/1987")]

    assert counts_by_type(findings) == {"EMAIL": 2, "DATE": 1}


def test_counts_by_type_empty() -> None:
    """No detections yields an empty mapping, not an error."""
    assert counts_by_type([]) == {}


def test_render_findings() -> None:
    """findings mode returns per-finding records and a tally."""
    findings = [_finding(), _finding("DATE", "03/14/1987", 20, 30)]

    result = render("findings", findings, "/tmp/export.csv")

    assert result["path"] == "/tmp/export.csv"
    assert result["mode"] == "findings"
    assert result["entity_count"] == 2
    assert result["counts"] == {"EMAIL": 1, "DATE": 1}
    assert len(result["findings"]) == 2


def test_render_clean_file() -> None:
    """A file with no PII renders zero counts rather than failing."""
    result = render("findings", [], "/tmp/clean.csv")

    assert result["entity_count"] == 0
    assert result["counts"] == {}
    assert result["findings"] == []


def test_render_rejects_unknown_mode() -> None:
    """An unrecognized mode is caller error, not a missing feature."""
    with pytest.raises(ValueError) as excinfo:
        render("bogus", [], "/tmp/x.csv")

    assert not isinstance(excinfo.value, UnsupportedMode)


@pytest.mark.parametrize("mode", ["summary", "content", "block"])
def test_render_rejects_unimplemented_mode(mode: str) -> None:
    """Declared but unbuilt modes raise UnsupportedMode."""
    with pytest.raises(UnsupportedMode):
        render(mode, [], "/tmp/x.csv")


def test_render_transformation_reports_only_the_tally() -> None:
    """
    A transformation response carries counts and never a value.

    Findings stand in for transformations: Transformation is final
    with a NoReturn constructor, so only the engine can build one, and
    the Labeled protocol is satisfied by both.
    """
    result = render_transformation(
        transformations=[_finding(), _finding("PHONE", "415-555-0182")],
        input_path="/tmp/export.csv",
        output_path="/tmp/export_redacted.csv",
        strategy="redact",
    )

    assert result["entity_count"] == 2
    assert result["counts"] == {"EMAIL": 1, "PHONE": 1}
    assert result["strategy"] == "redact"
    assert "josh@example.com" not in str(result)
