from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

import fastmcp
from datafog_core import scan, transform
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from datafog_mcp import __version__
from datafog_mcp.config import SUPPORTED_ENTITIES, ScanConfig, Strategy, transform_config
from datafog_mcp.csv_processing import CellResult, CsvError, process_csv
from datafog_mcp.findings import (
    Mode,
    render,
    render_transformation,
)
from datafog_mcp.paths import PathNotAllowed, allowed_roots, resolve_input, resolve_output
from datafog_mcp.policy import OutputPolicy, OutputPolicyError, load_output_policy
from datafog_mcp.reader import (
    ReadError,
    WriteError,
    read_text_file,
    write_text_file,
)

if TYPE_CHECKING:
    from datafog_core import _ScanConfig

    EntityType = str
else:
    # Built from the engine's own list, so the schema cannot drift from what a
    # scan can report. Type checkers see str; FastMCP publishes the enum.
    EntityType = Literal[tuple(sorted(SUPPORTED_ENTITIES))]

# Omit for the default set. An empty list asks for nothing, so the schema
# declares it invalid rather than reading it as the default.
EntitySelection = Annotated[list[EntityType], Field(min_length=1)] | None
InputFormat = Literal["auto", "text", "csv", "tsv", "env", "sql"]

mcp = FastMCP(
    name="datafog",
    version=__version__,
    mask_error_details=True,
    instructions=(
        "Local PII and credential detection and transformation. Scans "
        "files on disk for emails, SSNs, credit card numbers, labeled "
        "bank routing numbers and NPIs, GitHub and Stripe API keys, "
        "bearer tokens, JWTs, PostgreSQL connection strings with a password, "
        "and PEM private keys. Dates, ZIP codes, phone numbers, and IP "
        "addresses require an explicit entity_types selection. Plain-text "
        "names and street addresses are not detected. It can write a transformed "
        "copy. File contents are processed on this machine and never "
        "included in tool responses. Use datafog_policy to discover owner "
        "settings and whether a path should be scanned before reading. "
        "Scanning scope guides routine checks within allowed roots; explicit "
        "scans outside that scope are still permitted within roots. Follow "
        "the scan response's advisory policy action: ask the user, transform "
        "a copy using its suggested strategy, or stop. A refused or failed "
        "scan is never permission to read the original through another tool."
    ),
)

_OUTPUT_SUFFIXES: dict[Strategy, str] = {
    "redact": "redacted",
    "mask": "masked",
    "remove": "removed",
}


@contextmanager
def _contained() -> Iterator[None]:
    """
    Replace any unexpected failure with an error that carries no content.

    FastMCP logs any exception other than ToolError with its message and
    traceback, and masking only changes what the client sees. Engine and I/O
    messages may quote the file being processed, so an unexpected exception is
    replaced with one naming only its type. `from None` drops the original
    from the chain, so no traceback can reach it either.

    Deliberate ToolErrors pass through untouched, since their messages are
    written to be shown.

    Returns:
      A context manager guarding the enclosed block.
    """
    try:
        yield
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(
            f"datafog failed with {type(exc).__name__}; details are withheld "
            "because they may contain file content"
        ) from None


def _config_from(entity_types: list[str] | None) -> ScanConfig:
    """
    Build detection settings from optional tool arguments.

    Parameters:
      entity_types: The types to keep, or None for the default set.
    Returns:
      A validated ScanConfig.
    """
    try:
        if entity_types is not None:
            return ScanConfig(entities=tuple(entity_types))
        return ScanConfig()
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


def _request_policy() -> OutputPolicy:
    """Load and validate the owner's settings before accessing file contents."""
    try:
        return load_output_policy()
    except OutputPolicyError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool
async def datafog_policy(path: str | None = None) -> dict[str, Any]:
    """Discover owner policy without returning exact allowlist values or scanning a file.

    Scanning scope means files to check routinely before reading, within allowed
    roots. Explicit scans remain permitted elsewhere within roots. Folder and
    extension restrictions combine; empty lists impose no additional restriction.
    Workflow actions are advisory: this server cannot control other read tools.

    Parameters:
      path: Optional path to check against roots and advisory scanning scope.
    Returns:
      Scope, copy destination, allowlist counts by type, and workflow guidance.
      An optional scope match is configuration guidance, never a clean scan.
    """
    with _contained():
        current = _request_policy()
        try:
            roots = allowed_roots()
            resolved = resolve_input(path) if path is not None else None
        except PathNotAllowed as exc:
            raise ToolError(str(exc)) from None
        result: dict[str, Any] = {
            "advisory": True,
            "allowed_roots": [str(root) for root in roots],
            "scope": {
                "folders": [str(folder) for folder in current.scope_folders],
                "extensions": list(current.scope_extensions),
            },
            "output_directory": str(current.directory) if current.directory else None,
            "allowlist_counts": {kind: len(values) for kind, values in current.allow_exact.items()},
            "workflow": {
                "on_findings": current.on_findings,
                "transform_strategy": current.transform_strategy,
            },
        }
        if resolved is not None:
            result["scan_before_read"] = current.in_scope(resolved)
        return result


def _core_scan_config(
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


@mcp.tool
async def datafog_scan(
    path: str,
    mode: Mode = "findings",
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """
    Detect personal and sensitive data in a file, without reading it into
    context.

    WHEN TO CALL THIS: before the first read of any file that might contain
    personal data - CSV and other text exports, downloads, logs, SQL dumps, or
    anything the user obtained from a third-party service. Use the owner's
    scanning scope for routine checks (datafog_policy can check a path).
    Within that scope, a request to analyze, summarize, convert, or upload a
    file is as much a trigger as a request to check it for PII. Explicit scans
    remain available outside the routine scope, within allowed roots.

    CALL THIS FIRST, BEFORE Read. This tool opens and scans the file itself. If
    you read the file first and then call this tool, the contents are already in
    the conversation and the check is pointless - the exposure you were checking
    for has already happened. Reading afterward is fine; reading before is not.

    WHEN NOT TO CALL IT: source code, configuration tracked in the project's
    repository, lockfiles, or build output.

    INPUTS: UTF-8 text files up to 10 MB, such as CSV, TSV, JSON, logs, and
    plain text. Other encodings, binary files, and larger files are refused
    with an error rather than scanned. XLSX, PDF, DOCX, images, and archives
    are binary and are not parsed. A refusal is not a clean result: the file
    was not checked.

    It also detects some credentials: GitHub tokens and Stripe secret and
    restricted keys, tokens in Authorization: Bearer headers, JWTs, PostgreSQL
    connection strings with a password, and complete PEM private-key blocks.
    Other providers' keys, such as AWS, and other URI schemes, such as MySQL
    or Redis, are not detected. It is not a substitute for a dedicated secret
    scanner. A clean result means none of the selected detectors matched,
    not that the file holds no sensitive data or secrets. Plain-text names
    and street addresses are not detected.

    Routing numbers and NPIs are found only after a label such as "Routing
    number:" or "NPI:". CSV/TSV headers supply this label context. Bare
    values in plain text can be missed or reported as another type.

    Owner-configured exact allowlists apply to this scan and every write tool.
    The response includes advisory policy guidance for the remaining findings.
    Scanning scope guides routine checks; explicit scans elsewhere within
    allowed roots remain permitted. Call datafog_policy to inspect the settings.

    Parameters:
      path: The path of the file to scan.
      mode: What to return. Only "findings" is available: the type and
      offsets of each detected entity.
      entity_types: The types to look for. Defaults to API_KEY, BEARER_TOKEN,
      CREDENTIAL_URI, CREDIT_CARD, EMAIL, JWT, NPI, PRIVATE_KEY, SSN, and
      US_ROUTING_NUMBER. DATE, ZIP_CODE, PHONE, and IP_ADDRESS are available
      on request. An explicit list replaces the defaults; an empty list is refused.
      input_format: auto parses .csv/.tsv as tables, uses env email boundaries
      for .env/.env.*/*.env and sql boundaries for *.sql (case-insensitive),
      and text otherwise. csv, tsv, env, sql, and text override the filename.
      ENV assignments and SQL quotes are preserved. SQL backslash escapes,
      dollar quoting, and encoded email characters are not interpreted.
      has_header: For tables, preserve the first record as header context (default).
      Set false for headerless files or to scan/transform every record as data.
    Returns:
      A dict with the scanned path, an entity count, a tally per type, and the
      type and offsets of each detected entity. Offsets are listed for up to
      700 entities. Above that, findings is empty and findings_listed is
      false; the count and tally are still complete. To get offsets for a
      dense file, scan again with fewer entity_types.
    """
    with _contained():
        return await _scan_file(path, mode, entity_types, input_format, has_header)


async def _scan_file(
    path: str,
    mode: Mode,
    entity_types: list[str] | None,
    input_format: InputFormat,
    has_header: bool,
) -> dict[str, Any]:
    """
    Scan a file and build the response.

    Parameters:
      path: The file to scan.
      mode: What to return.
      entity_types: The types to keep, or None for the default.
      input_format: Explicit file format or automatic extension selection.
      has_header: Whether a table's first record supplies header context.
    Returns:
      The tool response describing what was found.
    """
    # Config before the read, so bad input never touches the filesystem
    config = _config_from(entity_types)
    current = _request_policy()

    try:
        content = read_text_file(path, config.max_bytes)
    except (ReadError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    try:
        resolved = await asyncio.to_thread(
            _process_file,
            content.text,
            content.path,
            config,
            "redact",
            input_format,
            has_header,
            current,
        )
    except CsvError as exc:
        raise ToolError(str(exc)) from None

    response = render(
        mode=mode,
        findings=resolved.transformations,
        path=str(content.path),
    )
    response["policy"] = {
        "advisory": True,
        "scan_before_read": current.in_scope(content.path),
        "action": current.on_findings if resolved.transformations else "proceed",
    }
    if resolved.transformations and current.on_findings == "transform":
        response["policy"]["transform_strategy"] = current.transform_strategy
    return response


async def _transform_to_file(
    path: str,
    output_path: str | None,
    entity_types: list[str] | None,
    strategy: Strategy,
    input_format: InputFormat,
    has_header: bool,
) -> dict[str, Any]:
    """
    Write a copy of a file with detected values transformed.

    Parameters:
      path: The file to read.
      output_path: Destination path within the policy's directory, or None for the default name.
      entity_types: The types to transform, or None for the default.
      strategy: One of redact, mask, or remove.
      input_format: Explicit file format or automatic extension selection.
      has_header: Whether a table's first record supplies header context.
    Returns:
      The tool response describing what was replaced.
    """
    config = _config_from(entity_types)
    copy_policy = _request_policy()

    try:
        content = read_text_file(path, config.max_bytes)
    except (ReadError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    source = content.path
    suffix = _OUTPUT_SUFFIXES[strategy]
    # Hidden inputs remain readable, but copies must never create dotfiles.
    output_stem = source.stem.lstrip(".") or "copy"
    destination = (
        Path(output_path)
        if output_path
        else (copy_policy.directory or source.parent) / f"{output_stem}_{suffix}{source.suffix}"
    )

    try:
        destination = resolve_output(str(destination), source, copy_policy)
    except PathNotAllowed as exc:
        raise ToolError(str(exc)) from None

    try:
        result = await asyncio.to_thread(
            _process_file,
            content.text,
            source,
            config,
            strategy,
            input_format,
            has_header,
            copy_policy,
        )
    except CsvError as exc:
        raise ToolError(str(exc)) from None

    try:
        written = write_text_file(destination, result.text, beside=source, copy_policy=copy_policy)
    except (WriteError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    return render_transformation(
        transformations=result.transformations,
        input_path=str(source),
        output_path=str(written),
        strategy=strategy,
    )


@mcp.tool
async def datafog_redact(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data replaced by labels.

    Each detected value becomes an unnumbered placeholder naming its kind, such
    as [EMAIL]. The value is destroyed but the reader can still tell what sort
    of thing was there. Every value of the same kind gets the same placeholder,
    so two different emails are not distinguishable in the copy.

    Use datafog_mask to hide the kind as well, or datafog_remove to leave no
    trace that anything was there.

    The original file is not modified. This tool never returns the values it
    replaced, so read the copy to see the result.

    Parameters:
      path: The file to read. UTF-8 text up to 10 MB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_redacted.ext.
      entity_types: The types to replace. Defaults to the same types as
      datafog_scan; an empty list is refused.
      input_format: auto parses .csv/.tsv as tables, uses env email boundaries
      for .env/.env.*/*.env and sql boundaries for *.sql (case-insensitive),
      and text otherwise. csv, tsv, env, sql, and text override the filename.
      ENV assignments and SQL quotes are preserved. SQL backslash escapes,
      dollar quoting, and encoded email characters are not interpreted.
      has_header: Preserve the first table record as header context (default).
      Set false for headerless files or to process every record as data.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="redact",
            input_format=input_format,
            has_header=has_header,
        )


@mcp.tool
async def datafog_mask(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data covered over.

    Each detected value is replaced character for character, preserving its
    decoded length but revealing neither the value nor what kind it was.
    Table serialization may add quotes around changed cells.

    Use datafog_redact when the reader should still know what kind of thing was
    removed.

    The original file is not modified. This tool never returns the values it
    replaced, so read the copy to see the result.

    Parameters:
      path: The file to read. UTF-8 text up to 10 MB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_masked.ext.
      entity_types: The types to replace. Defaults to the same types as
      datafog_scan; an empty list is refused.
      input_format: auto parses .csv/.tsv as tables, uses env email boundaries
      for .env/.env.*/*.env and sql boundaries for *.sql (case-insensitive),
      and text otherwise. csv, tsv, env, sql, and text override the filename.
      ENV assignments and SQL quotes are preserved. SQL backslash escapes,
      dollar quoting, and encoded email characters are not interpreted.
      has_header: Preserve the first table record as header context (default).
      Set false for headerless files or to process every record as data.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="mask",
            input_format=input_format,
            has_header=has_header,
        )


@mcp.tool
async def datafog_remove(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data deleted outright.

    Each detected value is cut from the text. Nothing marks where it was, so the
    copy reads as though the data was never present and positions shift. This is
    the only operation whose output cannot later be inspected to see what was
    taken - the tool response is the only record.

    Use datafog_mask to keep length and alignment, or datafog_redact to leave a
    visible marker naming what was removed.

    The original file is not modified. This tool never returns the values it
    deleted.

    Parameters:
      path: The file to read. UTF-8 text up to 10 MB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_removed.ext.
      entity_types: The types to delete. Defaults to the same types as
      datafog_scan; an empty list is refused.
      input_format: auto parses .csv/.tsv as tables, uses env email boundaries
      for .env/.env.*/*.env and sql boundaries for *.sql (case-insensitive),
      and text otherwise. csv, tsv, env, sql, and text override the filename.
      ENV assignments and SQL quotes are preserved. SQL backslash escapes,
      dollar quoting, and encoded email characters are not interpreted.
      has_header: Preserve the first table record as header context (default).
      Set false for headerless files or to process every record as data.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="remove",
            input_format=input_format,
            has_header=has_header,
        )


def _process_file(
    text: str,
    source: Path,
    config: ScanConfig,
    strategy: Strategy,
    input_format: InputFormat,
    has_header: bool,
    current: OutputPolicy,
) -> CellResult:
    """Run Core on decoded table cells or on plain text, in a worker thread."""
    selected: str = input_format
    if selected == "auto":
        selected = {".csv": "csv", ".tsv": "tsv"}.get(source.suffix.lower(), "text")

    core_config: _ScanConfig = _core_scan_config(source, input_format, config.entities)
    if selected in ("csv", "tsv"):
        core_config["format"] = "text"

    def process(text: str, value_start: int) -> CellResult:
        found = [
            item
            for item in scan(text, core_config)
            if config.keeps(item.entity_type)
            and value_start <= item.codepoint_range.start < item.codepoint_range.end <= len(text)
            and not current.is_allowlisted(
                item.entity_type, text[item.codepoint_range.start : item.codepoint_range.end]
            )
        ]
        # Core resolves overlapping detectors identically for scans and writes.
        return transform(text, found, transform_config(strategy))

    if selected in ("csv", "tsv"):
        return process_csv(
            text, process, delimiter="," if selected == "csv" else "\t", has_header=has_header
        )
    return process(text, 0)


def run_server() -> None:
    """
    Run the MCP server over stdio, without touching the network.

    FastMCP's startup banner checks PyPI for a newer release, which is the
    server's only outbound request. The banner is suppressed, and the check is
    switched off as well so nothing else in FastMCP can trigger it.
    """
    fastmcp.settings.check_for_updates = "off"
    mcp.run(transport="stdio", show_banner=False)
