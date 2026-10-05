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
from datafog_mcp.findings import (
    Mode,
    render,
    render_transformation,
)
from datafog_mcp.paths import PathNotAllowed, resolve_output
from datafog_mcp.policy import OutputPolicyError, load_output_policy
from datafog_mcp.reader import (
    ReadError,
    WriteError,
    read_text_file,
    write_text_file,
)

if TYPE_CHECKING:
    EntityType = str
else:
    # Built from the engine's own list, so the schema cannot drift from what a
    # scan can report. Type checkers see str; FastMCP publishes the enum.
    EntityType = Literal[tuple(sorted(SUPPORTED_ENTITIES))]

# Omit for the default set. An empty list asks for nothing, so the schema
# declares it invalid rather than reading it as the default.
EntitySelection = Annotated[list[EntityType], Field(min_length=1)] | None

mcp = FastMCP(
    name="datafog",
    version=__version__,
    mask_error_details=True,
    instructions=(
        "Local PII and credential detection and transformation. Scans "
        "files on disk for emails, phone numbers, SSNs, credit card "
        "numbers, dates, ZIP codes, bank routing numbers, NPIs, API "
        "keys, tokens, and private keys, and can write a transformed "
        "copy. File contents are processed on this machine and never "
        "included in tool responses."
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


@mcp.tool
async def datafog_scan(
    path: str,
    mode: Mode = "findings",
    entity_types: EntitySelection = None,
) -> dict[str, Any]:
    """
    Detect personal and sensitive data in a file, without reading it into
    context.

    WHEN TO CALL THIS: before the first read of any file that might contain
    personal data - CSV and other text exports, downloads, logs, SQL dumps, or
    anything the user obtained from a third-party service. Call it
    regardless of what the user asked for. A request to analyze, summarize,
    convert, or upload a file is as much a trigger as a request to check it for
    PII.

    CALL THIS FIRST, BEFORE Read. This tool opens and scans the file itself. If
    you read the file first and then call this tool, the contents are already in
    the conversation and the check is pointless - the exposure you were checking
    for has already happened. Reading afterward is fine; reading before is not.

    WHEN NOT TO CALL IT: source code, configuration tracked in the project's
    repository, lockfiles, or build output.

    INPUTS: UTF-8 text files up to 1 MiB, such as CSV, TSV, JSON, logs, and
    plain text. Other encodings, binary files, and larger files are refused
    with an error rather than scanned. XLSX, PDF, DOCX, images, and archives
    are binary and are not parsed. A refusal is not a clean result: the file
    was not checked.

    It also detects common credentials - API keys, bearer tokens, JWTs,
    credentials embedded in URIs, and PEM private keys - but is not a
    substitute for a dedicated secret scanner. A clean result means none of
    these detectors matched, not that the file holds no secrets.

    Parameters:
      path: The path of the file to scan.
      mode: What to return. Only "findings" is available: the type and
      offsets of each detected entity.
      entity_types: The types to look for. Defaults to API_KEY, BEARER_TOKEN,
      CREDENTIAL_URI, CREDIT_CARD, DATE, EMAIL, JWT, NPI, PHONE, PRIVATE_KEY,
      SSN, US_ROUTING_NUMBER, and ZIP_CODE. IP_ADDRESS is available on
      request. Omit for the defaults; an empty list is refused.
    Returns:
      A dict with the scanned path, an entity count, a tally per type, and the
      detected entities.
    """
    with _contained():
        return await _scan_file(path, mode, entity_types)


async def _scan_file(
    path: str,
    mode: Mode,
    entity_types: list[str] | None,
) -> dict[str, Any]:
    """
    Scan a file and build the response.

    Parameters:
      path: The file to scan.
      mode: What to return.
      entity_types: The types to keep, or None for the default.
    Returns:
      The tool response describing what was found.
    """
    # Config before the read, so bad input never touches the filesystem
    config = _config_from(entity_types)

    try:
        content = read_text_file(path, config.max_bytes)
    except (ReadError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    found = await asyncio.to_thread(scan, content.text)
    kept = [item for item in found if config.keeps(item.entity_type)]

    # The engine reports every detector's match, so one value can appear
    # twice: an NPI is also a valid phone number. Transforming resolves those
    # overlaps, so the scan reports exactly the spans the write tools replace.
    # The transformed text is discarded.
    resolved = await asyncio.to_thread(transform, content.text, kept, transform_config("redact"))

    return render(
        mode=mode,
        findings=resolved.transformations,
        path=str(content.path),
    )


async def _transform_to_file(
    path: str,
    output_path: str | None,
    entity_types: list[str] | None,
    strategy: Strategy,
) -> dict[str, Any]:
    """
    Write a copy of a file with detected values transformed.

    Parameters:
      path: The file to read.
      output_path: Destination path within the policy's directory, or None for the default name.
      entity_types: The types to transform, or None for the default.
      strategy: One of redact, mask, or remove.
    Returns:
      The tool response describing what was replaced.
    """
    config = _config_from(entity_types)

    try:
        content = read_text_file(path, config.max_bytes)
    except (ReadError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    try:
        copy_policy = load_output_policy()
    except OutputPolicyError as exc:
        raise ToolError(str(exc)) from None

    source = content.path
    suffix = _OUTPUT_SUFFIXES[strategy]
    destination = (
        Path(output_path)
        if output_path
        else (copy_policy.directory or source.parent) / f"{source.stem}_{suffix}{source.suffix}"
    )

    try:
        destination = resolve_output(str(destination), source, copy_policy)
    except PathNotAllowed as exc:
        raise ToolError(str(exc)) from None

    found = await asyncio.to_thread(scan, content.text)
    kept = [item for item in found if config.keeps(item.entity_type)]

    result = await asyncio.to_thread(transform, content.text, kept, transform_config(strategy))

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
      path: The file to read. UTF-8 text up to 1 MiB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_redacted.ext.
      entity_types: The types to replace. Defaults to the same types as
      datafog_scan; an empty list is refused.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="redact",
        )


@mcp.tool
async def datafog_mask(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data covered over.

    Each detected value is replaced character for character, so the copy keeps
    the original length and column alignment but reveals neither the value nor
    what kind of value it was.

    Use datafog_redact when the reader should still know what kind of thing was
    removed.

    The original file is not modified. This tool never returns the values it
    replaced, so read the copy to see the result.

    Parameters:
      path: The file to read. UTF-8 text up to 1 MiB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_masked.ext.
      entity_types: The types to replace. Defaults to the same types as
      datafog_scan; an empty list is refused.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="mask",
        )


@mcp.tool
async def datafog_remove(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
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
      path: The file to read. UTF-8 text up to 1 MiB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_removed.ext.
      entity_types: The types to delete. Defaults to the same types as
      datafog_scan; an empty list is refused.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="remove",
        )


def run_server() -> None:
    """
    Run the MCP server over stdio, without touching the network.

    FastMCP's startup banner checks PyPI for a newer release, which is the
    server's only outbound request. The banner is suppressed, and the check is
    switched off as well so nothing else in FastMCP can trigger it.
    """
    fastmcp.settings.check_for_updates = "off"
    mcp.run(transport="stdio", show_banner=False)
