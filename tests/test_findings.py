"""Tests for datafog_mcp.findings."""

from __future__ import annotations

import pytest
from datafog.engine import Entity

from datafog_mcp.findings import (
    UnsupportedMode,
    counts_by_type,
    entity_to_dict,
    render,
)


def _entity(
    entity_type: str = "EMAIL",
    text: str = "josh@example.com",
    start: int = 0,
    end: int = 16,
) -> Entity:
    """
    Build a detection record for testing.

    Parameters:
      entity_type: Detected entity type.
      text: Matched substring.
      start: Start offset in the source text.
      end: End offset in the source text.
    Returns:
      A populated Entity.
    """
    return Entity(
        type=entity_type,
        text=text,
        start=start,
        end=end,
        confidence=0.99,
        engine="regex",
    )


def test_entity_to_dict_maps_fields() -> None:
    """Every Entity field reaches the output record."""
    assert entity_to_dict(_entity()) == {
        "type": "EMAIL",
        "value": "josh@example.com",
        "start": 0,
        "end": 16,
        "confidence": 0.99,
        "engine": "regex",
    }


def test_counts_by_type_tallies() -> None:
    """Repeated types accumulate; distinct types stay separate."""
    entities = [_entity(), _entity(), _entity("DOB", "03/14/1987")]

    assert counts_by_type(entities) == {"EMAIL": 2, "DOB": 1}


def test_counts_by_type_empty() -> None:
    """No detections yields an empty mapping, not an error."""
    assert counts_by_type([]) == {}


def test_render_findings() -> None:
    """findings mode returns per-entity records and a tally."""
    entities = [_entity(), _entity("DOB", "03/14/1987", 20, 30)]

    result = render("findings", entities, "/tmp/export.csv", "regex")

    assert result["path"] == "/tmp/export.csv"
    assert result["mode"] == "findings"
    assert result["entity_count"] == 2
    assert result["counts"] == {"EMAIL": 1, "DOB": 1}
    assert result["engine_used"] == "regex"
    assert len(result["entities"]) == 2


def test_render_clean_file() -> None:
    """A file with no PII renders zero counts rather than failing."""
    result = render("findings", [], "/tmp/clean.csv", "regex")

    assert result["entity_count"] == 0
    assert result["counts"] == {}
    assert result["entities"] == []


def test_render_rejects_unknown_mode() -> None:
    """An unrecognized mode is caller error, not a missing feature."""
    with pytest.raises(ValueError) as excinfo:
        render("bogus", [], "/tmp/x.csv", "regex")

    assert not isinstance(excinfo.value, UnsupportedMode)


@pytest.mark.parametrize("mode", ["summary", "content", "block"])
def test_render_rejects_unimplemented_mode(mode: str) -> None:
    """Declared but unbuilt modes raise UnsupportedMode."""
    with pytest.raises(UnsupportedMode):
        render(mode, [], "/tmp/x.csv", "regex")
