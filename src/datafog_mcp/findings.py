"""
Rendering scan and transformation results for the datafog tools.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, Protocol

from datafog_core import Finding

# The only mode built. The schema is generated from this, so a mode listed
# here is a promise to the agent; add one only alongside its implementation.
Mode = Literal["findings"]


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


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    """
    Convert a detection into a serializable record.

    Deliberately omits matched_text. The tool reports where something is and
    what kind it is; returning the value would put into context exactly what
    path-based scanning exists to keep out.

    Parameters:
      finding: A single detection from datafog_core.scan.
    Returns:
      A dict with the entity type and the span it occupies.
    """
    return {
        "type": finding.entity_type,
        "start": finding.codepoint_range.start,
        "end": finding.codepoint_range.end,
    }


def render(
    mode: Mode,
    findings: Sequence[Any],
    path: str,
) -> dict[str, Any]:
    """
    Build the tool response for a completed scan.

    Parameters:
      mode: The requested return mode.
      findings: Detections from the scan.
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
