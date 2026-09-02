"""
Rendering scan results for the datafog_scan tool.
"""

from __future__ import annotations

from typing import Any, Literal

from datafog.engine import Entity

Mode = Literal["findings", "summary", "content", "block"]

VALID_MODES: frozenset[str] = frozenset({"findings", "summary", "content", "block"})

IMPLEMENTED_MODES: frozenset[str] = frozenset({"findings"})


class UnsupportedMode(ValueError):
    """The mode is recognized but not implemented yet."""


def entity_to_dict(entity: Entity) -> dict[str, Any]:
    """
    Convert a detected entity into a serializable record.

    Parameters:
      entity: A single detection from datafog.engine.scan.
    Returns:
      A dict containing the type, matched value, offsets, confidence, and the
      engine that produced it.
    """
    return {
        "type": entity.type,
        "value": entity.text,
        "start": entity.start,
        "end": entity.end,
        "confidence": entity.confidence,
        "engine": entity.engine,
    }


def counts_by_type(entities: list[Entity]) -> dict[str, int]:
    """
    Tally detections per entity type.

    Parameters:
      entities: Detections from a single scan.
    Returns:
      A mapping of entity type to occurrence count.
    """
    counts: dict[str, int] = {}
    for entity in entities:
        counts[entity.type] = counts.get(entity.type, 0) + 1
    return counts


def validate_mode(mode: str) -> None:
    """
    Reject modes that are unknown or not implemented yet.

    Parameters:
      mode: The requested return mode.
    Returns:
      None. Raises on invalid input.
    """
    if mode not in VALID_MODES:
        raise ValueError("Not a valid mode.")

    if mode not in IMPLEMENTED_MODES:
        raise UnsupportedMode("Not yet an implemented mode.")


def render(
    mode: str,
    entities: list[Entity],
    path: str,
    engine_used: str,
) -> dict[str, Any]:
    """
    Build the tool response for a completed scan.

    Parameters:
      mode: The requested return mode.
      entities: Detections from the scan.
      path: The file that was scanned.
      engine_used: The detector chain reported by the engine.
    Returns:
      A dict representing what was found, shaped by the mode.
    """
    validate_mode(mode)

    return {
        "path": path,
        "mode": mode,
        "entity_count": len(entities),
        "counts": counts_by_type(entities),
        "engine_used": engine_used,
        "entities": [entity_to_dict(e) for e in entities],
    }


def render_redaction(
    entities: list[Entity],
    input_path: str,
    output_path: str,
    strategy: str,
    engine: str,
) -> dict[str, Any]:
    """
    Build the tool responses for a completed redaction.

    Does not use entity_to_dict because it carries entity.text.

    Parameters:
      entities: Detections the engine replaced.
      input_path: The file that was read.
      output_path: The file that was written.
      strategy: The engine strategy applied.
      engine: The detector engine requested.
    Returns:
      A dict describing what was replaced, carrying no matched value.
    """
    return {
        "input_path": input_path,
        "output_path": output_path,
        "entity_count": len(entities),
        "counts": counts_by_type(entities),
        "strategy": strategy,
        "engine": engine,
    }
