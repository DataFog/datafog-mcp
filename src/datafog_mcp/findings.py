"""
Rendering scan and transformation results for the datafog tools.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from datafog_core import TextRange

# The only mode built. The schema is generated from this, so a mode listed
# here is a promise to the agent; add one only alongside its implementation.
Mode = Literal["findings"]


@dataclass(frozen=True)
class CsvFinding:
    """A content-free location in a table's original source text."""

    entity_type: str
    source_codepoint_range: TextRange
    record: int
    column: int


class Labeled(Protocol):
    """
    Anything carrying an entity type: a finding or a transformation.
    """

    @property
    def entity_type(self) -> str:
        """
        The label the detector assigned.

        Returns:
          An entity type such as EMAIL.
        """
        ...


def counts_by_type(items: Sequence[Labeled]) -> dict[str, int]:
    """
    Tally findings or transformations per entity type.

    Parameters:
      items: Detections from a scan, or replacements from a transform.
    Returns:
      A mapping of entity type to occurrence count.
    """
    counts: dict[str, int] = {}
    for item in items:
        counts[item.entity_type] = counts.get(item.entity_type, 0) + 1
    return counts


class Located(Labeled, Protocol):
    """
    A labeled span of the source text, such as a transformation.
    """

    @property
    def source_codepoint_range(self) -> TextRange:
        """
        Where the value sat in the text that was scanned.

        Returns:
          The span in codepoints.
        """
        ...


def finding_to_dict(finding: Located) -> dict[str, Any]:
    """
    Convert a detection into a serializable record.

    Takes a transformation, which carries no matched text, so the record
    cannot include the value. The tool reports where something is and what
    kind it is; returning the value would put into context exactly what
    path-based scanning exists to keep out.

    Parameters:
      finding: A detection, as resolved by datafog_core.transform.
    Returns:
      A dict with the entity type and the span it occupies.
    """
    result: dict[str, Any] = {
        "type": finding.entity_type,
        "start": finding.source_codepoint_range.start,
        "end": finding.source_codepoint_range.end,
    }
    # Only location metadata is exposed; headers themselves can contain PII.
    if isinstance(finding, CsvFinding):
        result.update(record=finding.record, column=finding.column)
    return result


def render(
    mode: Mode,
    findings: Sequence[Located],
    path: str,
) -> dict[str, Any]:
    """
    Build the tool response for a completed scan.

    Parameters:
      mode: The requested return mode.
      findings: Detections, with overlapping matches already resolved.
      path: The file that was scanned.
    Returns:
      A dict representing what was found, shaped by the mode.
    """
    return {
        "path": path,
        "mode": mode,
        "entity_count": len(findings),
        "counts": counts_by_type(findings),
        "findings": [finding_to_dict(item) for item in findings],
    }


def render_transformation(
    transformations: Sequence[Labeled],
    input_path: str,
    output_path: str,
    strategy: str,
) -> dict[str, Any]:
    """
    Build the tool response for a completed transformation.

    Takes transformations rather than findings: datafog_core's Transformation
    carries no matched text at all, so this tally cannot leak a value even by
    accident.

    Parameters:
      transformations: Replacements the engine applied.
      input_path: The file that was read.
      output_path: The file that was written.
      strategy: The engine strategy applied.
    Returns:
      A dict describing what was replaced, carrying no matched value.
    """
    return {
        "input_path": input_path,
        "output_path": output_path,
        "entity_count": len(transformations),
        "counts": counts_by_type(transformations),
        "strategy": strategy,
    }
