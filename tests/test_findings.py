"""Tests for datafog_mcp.findings."""

from __future__ import annotations

from datafog_core import Transformation, scan, transform

from datafog_mcp.config import transform_config
from datafog_mcp.findings import (
    counts_by_type,
    finding_to_dict,
    render,
    render_transformation,
)


def _resolved(text: str) -> list[Transformation]:
    """
    Detect and resolve the values in a string, as the tools do.

    Transformation has no public constructor, so the engine builds them.

    Parameters:
      text: Source text holding the values.
    Returns:
      The engine's transformations, in source order.
    """
    return list(transform(text, scan(text), transform_config("redact")).transformations)


def test_finding_to_dict_omits_the_matched_value() -> None:
    """
    The record locates a finding without disclosing it.

    Returning matched_text would put into context exactly what
    path-based scanning exists to keep out.
    """
    record = finding_to_dict(_resolved("josh@example.com")[0])

    assert record == {"type": "EMAIL", "start": 0, "end": 16}
    assert "josh@example.com" not in str(record)


def test_counts_by_type_tallies() -> None:
    """Repeated types accumulate; distinct types stay separate."""
    findings = _resolved("josh@example.com amy@example.com 03/14/1987")

    assert counts_by_type(findings) == {"EMAIL": 2, "DATE": 1}


def test_counts_by_type_empty() -> None:
    """No detections yields an empty mapping, not an error."""
    assert counts_by_type([]) == {}


def test_render_findings() -> None:
    """findings mode returns per-finding records and a tally."""
    findings = _resolved("josh@example.com    03/14/1987")

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


def test_render_transformation_reports_only_the_tally() -> None:
    """A transformation response carries counts and never a value."""
    result = render_transformation(
        transformations=_resolved("josh@example.com 415-555-0182"),
        input_path="/tmp/export.csv",
        output_path="/tmp/export_redacted.csv",
        strategy="redact",
    )

    assert result["entity_count"] == 2
    assert result["counts"] == {"EMAIL": 1, "PHONE": 1}
    assert result["strategy"] == "redact"
    assert "josh@example.com" not in str(result)
