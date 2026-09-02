from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from datafog.engine import scan, scan_and_redact
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from datafog_mcp.config import ScanConfig
from datafog_mcp.findings import Mode, render, render_redaction, validate_mode
from datafog_mcp.paths import PathNotAllowed
from datafog_mcp.reader import (
    ReadError,
    WriteError,
    read_text_file,
    write_text_file,
)

mcp = FastMCP(
    name="datafog",
    version="0.1.0",
    instructions=(
        "Local PII detection. Scans files on disk for emails, phone numbers, "
        "SSNs, credit card numbers, dates of birth, and postal codes. Can write "
        "a masked or tokenized copy. Runs locally. No data is sent anywhere."
    ),
)

_OUTPUT_SUFFIXES: dict[str, str] = {"mask": "redacted", "token": "anonymized"}


def _config_from(
    engine: str | None,
    entity_types: list[str] | None,
) -> ScanConfig:
    """
    Build detection settings from optional tool arguments.

    Parameters:
      engine: The detector engine, or None for the default.
      entity_types: The types to look for, or None for the default.
    Returns:
      A validated ScanConfig.
    """
    overrides: dict[str, Any] = {}
    if engine is not None:
        overrides["engine"] = engine
    if entity_types:
        overrides["entities"] = tuple(entity_types)

    try:
        return ScanConfig(**overrides)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool
async def datafog_scan(
    path: str,
    mode: Mode = "findings",
    engine: str | None = None,
    entity_types: list[str] | None = None,
) -> dict[str, Any]:
    """
    Detect personal and sensitive data in a file, without reading it
    into context.

    WHEN TO CALL THIS: before the first read of any file that might
    contain personal data - exports, downloads, spreadsheets, logs,
    database dumps, backups, or anything the user obtained from a
    third-party service. Call it regardless of what the user asked
    for. A request to analyze, summarize, convert, or upload a file
    is as much a trigger as a request to check it for PII.

    CALL THIS FIRST, BEFORE Read. This tool opens and scans the file
    itself. If you read the file first and then call this tool, the
    contents are already in the conversation and the check is
    pointless - the exposure you were checking for has already
    happened. Reading afterward is fine; reading before is not.

    WHEN NOT TO CALL IT: source code, configuration tracked in the
    project's repository, lockfiles, or build output. It detects
    structured identifiers, not secrets - it will not find API keys,
    tokens, or private keys.

    Parameters:
      path: The path of the file to scan.
      mode: What to return.
      engine: The detector engine to use. Defaults to "regex".
      entity_types: The types to look for. Default to EMAIL, PHONE, SSN,
      CREDIT_CARD, DOB, and ZIP.
    Returns:
      A dict with the scanned path, an entity count, a tally per type, and the
      detected entities.
    """

    # Deliberate validation order: mode, then config, then file read
    try:
        validate_mode(mode)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc

    config = _config_from(engine, entity_types)

    try:
        content = read_text_file(path, config.max_bytes)
    except (ReadError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    # datafog.engine.scan is synchronous
    result = await asyncio.to_thread(
        scan,
        text=content.text,
        engine=config.engine,
        entity_types=list(config.entities),
    )

    return render(
        mode=mode,
        entities=result.entities,
        path=str(content.path),
        engine_used=result.engine_used,
    )


async def _redact_to_file(
    path: str,
    output_path: str | None,
    engine: str | None,
    entity_types: list[str] | None,
    strategy: str,
) -> dict[str, Any]:
    """
    Write a copy of a file with detected values replaced.

    Parameters:
      path: The file to read.
      output_path: Where to write, or None for a sibling of the input.
      engine: The detector engine, or None for the default.
      entity_types: The types to replace, or None for the default.
      strategy: The engine redaction strategy.
    Returns:
      The tool response describing what was replaced.
    """
    config = _config_from(engine, entity_types)

    try:
        content = read_text_file(path, config.max_bytes)
    except (ReadError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    source = content.path
    destination = (
        Path(output_path)
        if output_path
        else source.with_name(f"{source.stem}_{_OUTPUT_SUFFIXES[strategy]}{source.suffix}")
    )

    result = await asyncio.to_thread(
        scan_and_redact,
        text=content.text,
        engine=config.engine,
        entity_types=list(config.entities),
        strategy=strategy,
    )

    # RedactResult.mapping holds plaintext under every strategy, including mask.
    # Only redacted_text is read.
    try:
        written = write_text_file(destination, result.redacted_text)
    except (WriteError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    return render_redaction(
        entities=result.entities,
        input_path=str(source),
        output_path=str(written),
        strategy=strategy,
        engine=config.engine,
    )


@mcp.tool
async def datafog_redact(
    path: str,
    output_path: str | None = None,
    engine: str | None = None,
    entity_types: list[str] | None = None,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data masked out (redacted).

    Masking replaces each detected value with asterisks of the same length. It
    destroys the value and its type together: the copy shows that something was
    removed, not what kind of thing it was. Use this when the removed values
    never need to be told apart.

    Use datafog_anonymize instead when the copy has to preserve which value was
    which.

    The original file is not modified. This tool never returns the values it
    replaced, so the coyp must be read to see the result.

    Parameters:
      path: The file to read.
      output_path: Where to write. Defaults to a sibling of the input with a
      _redacted suffix.
      engine: The detector engine to use. Defaults to "regex".
      entity_types: The types to replace. Defaults to EMAIL, Phone, SSN,
      CREDIT_CARD, DOB, and ZIP.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    return await _redact_to_file(
        path,
        output_path,
        engine,
        entity_types,
        strategy="mask",
    )


@mcp.tool
async def datafog_anonymize(
    path: str,
    output_path: str | None = None,
    engine: str | None = None,
    entity_types: list[str] | None = None,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data replaced by placeholders.

    Each detected value becomes a numbered placeholder like [EMAIL_1]. The
    value is destroyed but its type survives, and two different values get two
    different placeholders. Use this when the copy still has to support
    reasoning about which value was which - counting distinct people, following
    one person through a log.

    Use datafog_redact instead when even the type should not survive.

    The original file is not modified. This tool never returns the values it
    replaced, and the placeholders cannot be reversed.

    Parameters:
      path: The file to read.
      output_path: Where to write. Defaults to a sibling of the input with an
      _anonymized suffix.
      engine: The detector engine to use. Defaults to "regex".
      entity_types: The types to replace. Defaults to EMAIL, PHONE, SSN,
      CREDIT_CARD, DOB, and ZIP.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    return await _redact_to_file(
        path,
        output_path,
        engine,
        entity_types,
        strategy="token",
    )


def run_server() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")
