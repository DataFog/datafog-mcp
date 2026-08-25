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
    Checks a file for PII.

    Call this before reading a file that might hold PII, and before sending any
    part of it to an external service. This opens and scans the file itself, so
    do not read the file first. Otherwise the file contents would get placed in
    context before being checked.

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
