"""
Detection over plain text and decoded table cells, without the MCP server.

The tools in server.py and the public interface in api.py both run this one
pipeline, so a scan, a write, and an embedding program agree on what was
found. Nothing here returns a matched value: results carry entity types and
positions, and the transformed text.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from datafog_core import DataFogFindingError, scan, transform

from .config import ScanConfig, Strategy, transform_config
from .csv_processing import CellResult, process_csv
from .policy import OutputPolicy

if TYPE_CHECKING:
    from datafog_core import Finding, TransformResult, _ScanConfig, _TransformationConfig

InputFormat = Literal["auto", "text", "csv", "tsv", "env", "sql"]

# The engine calls, as parameters: the server passes its own module-level
# names so its tests can replace them and see every failure path.
ScanFunction = Callable[[str, "_ScanConfig"], "list[Finding]"]
TransformFunction = Callable[[str, "Sequence[Finding]", "_TransformationConfig"], "TransformResult"]


class OverlapConflict(ValueError):
    """Detections partly overlap; the message names entity types, never values."""


def _overlap_conflict(found: list[Finding], index: int | None) -> OverlapConflict:
    """
    Describe a refused overlap without quoting the text.

    Core 1.x refuses to transform when two detections partly overlap and
    neither contains the other: replacing either one alone would leave the
    rest of the other in the copy. The request fails the same way rather
    than choose, and names only the entity types involved so the caller can
    narrow entity_types.

    Parameters:
      found: The findings passed to the engine.
      index: The engine's index of a finding it could not cover, if given.
    Returns:
      An error whose message is safe to show.
    """
    kinds: set[str] = set()
    if index is not None and 0 <= index < len(found):
        target = found[index].codepoint_range
        kinds = {
            item.entity_type
            for item in found
            if item.codepoint_range.start < target.end and target.start < item.codepoint_range.end
        }
    named = f" ({', '.join(sorted(kinds))})" if kinds else ""
    return OverlapConflict(
        f"Detections of different types partly overlap{named}, so replacing one would "
        "leave part of another in place. No result was produced and no copy was written. "
        "Retry with a narrower entity_types selection."
    )


def core_scan_config(
    path: Path, input_format: InputFormat, entities: tuple[str, ...]
) -> _ScanConfig:
    """Select Core detectors and email boundaries before scanning.

    Auto recognizes .env, .env.*, *.env, and *.sql filenames, ignoring case.
    Other files retain plain-text boundaries, including CSV and TSV files.
    An explicit format overrides the filename.
    """
    selected_entities = list(dict.fromkeys(entities))
    if input_format in ("text", "env", "sql"):
        return {"format": input_format, "entities": selected_entities}
    if input_format in ("csv", "tsv"):
        return {"format": "text", "entities": selected_entities}
    name = path.name.lower()
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return {"format": "env", "entities": selected_entities}
    if name.endswith(".sql"):
        return {"format": "sql", "entities": selected_entities}
    return {"format": "text", "entities": selected_entities}


def process_with_engine(
    text: str,
    source: Path,
    config: ScanConfig,
    strategy: Strategy,
    input_format: InputFormat,
    has_header: bool,
    current: OutputPolicy,
    scan_text: ScanFunction,
    transform_text: TransformFunction,
) -> CellResult:
    """
    Run the given engine calls on decoded table cells or on plain text.

    This is the seam the server uses; other callers want process_text.

    Parameters:
      text: The decoded text to process.
      source: The path the text came from; only its name selects a format.
      config: The entity types to detect.
      strategy: How detected values are replaced in the returned text.
      input_format: An explicit format, or auto to go by the filename.
      has_header: Whether a table's first record supplies header context.
      current: The policy snapshot whose exact allowlists apply.
      scan_text: The engine's scan call.
      transform_text: The engine's transform call.
    Returns:
      The transformed text and the content-free locations of what changed.
    """
    selected: str = input_format
    if selected == "auto":
        selected = {".csv": "csv", ".tsv": "tsv"}.get(source.suffix.lower(), "text")

    core_config: _ScanConfig = core_scan_config(source, input_format, config.entities)
    if selected in ("csv", "tsv"):
        core_config["format"] = "text"

    def process(text: str, value_start: int) -> CellResult:
        found = [
            item
            for item in scan_text(text, core_config)
            if config.keeps(item.entity_type)
            and value_start <= item.codepoint_range.start < item.codepoint_range.end <= len(text)
            and not current.is_allowlisted(
                item.entity_type, text[item.codepoint_range.start : item.codepoint_range.end]
            )
        ]
        # Core resolves overlapping detectors identically for scans and writes.
        try:
            return transform_text(text, found, transform_config(strategy))
        except DataFogFindingError as exc:
            # Any other finding error is unexpected and may quote the text,
            # so it is left for the caller to contain.
            if getattr(exc, "code", None) != "review_conflict":
                raise
            raise _overlap_conflict(found, getattr(exc, "finding_index", None)) from None

    if selected in ("csv", "tsv"):
        return process_csv(
            text, process, delimiter="," if selected == "csv" else "\t", has_header=has_header
        )
    return process(text, 0)


def process_text(
    text: str,
    *,
    policy: OutputPolicy,
    source: str | Path = "",
    config: ScanConfig | None = None,
    strategy: Strategy = "redact",
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> CellResult:
    """
    Detect selected entity types in text and return it transformed.

    Runs the pipeline the datafog tools run: CSV and TSV are processed cell by
    cell with header context, exact allowlists from the policy are applied
    before overlaps are resolved, and ENV and SQL filenames select their email
    boundaries.

    The result's transformations give each detection's entity type and its
    position in the original text; table results also give the one-based data
    record and column. They never carry the matched value or header text. The
    result's text is the input with each detection replaced according to the
    strategy, so it still holds everything that was not detected. A caller
    that only wants to know what was found should read transformations and
    discard text.

    Engine and parsing failures other than CsvError and OverlapConflict may
    quote the text in their messages; callers that report errors should name
    only the exception type, as the server does.

    Parameters:
      text: The decoded text to process.
      policy: A snapshot from load_policy; its exact allowlists apply.
      source: The path or filename the text came from. Only the name is used,
      to choose a format when input_format is auto; nothing is read from disk.
      config: The entity types to detect, or None for the defaults.
      strategy: redact, mask, or remove.
      input_format: auto, text, csv, tsv, env, or sql.
      has_header: Whether a table's first record is a header.
    Returns:
      The transformed text and the content-free locations of what changed.
    Raises:
      CsvError: The table is malformed; the message has locations only.
      OverlapConflict: Detections partly overlap; the message has types only.
    """
    return process_with_engine(
        text,
        Path(source),
        config if config is not None else ScanConfig(),
        strategy,
        input_format,
        has_header,
        policy,
        scan,
        transform,
    )
