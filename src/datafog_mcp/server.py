from __future__ import annotations

import asyncio
from typing import Any

from datafog.engine import scan
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from datafog_mcp.config import ScanConfig
from datafog_mcp.findings import Mode, render, validate_mode
from datafog_mcp.reader import ReadError, read_text_file

mcp = FastMCP(
    name="datafog",
    version="0.1.0",
    instructions=(
        "Local PII detection. Scans files on disk for emails, phone numbers, "
        "SSNs, credit card numbers, dates of birth, and postal codes. Runs "
        "locally. No data is sent anywhere."
    ),
)


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

    overrides: dict[str, Any] = {}
    if engine is not None:
        overrides["engine"] = engine
    if entity_types:
        overrides["entities"] = tuple(entity_types)

    try:
        config = ScanConfig(**overrides)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc

    try:
        content = read_text_file(path, config.max_bytes)
    except ReadError as exc:
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


def run_server() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")
