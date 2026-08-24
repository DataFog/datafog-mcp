from __future__ import annotations

from typing import Any

from datafog.engine import scan
from fastmcp import FastMCP

mcp = FastMCP(
    name="datafog",
    version="0.1.0",
    instructions=(
        "PII detection tools. Scan text for emails, SSNs, names, phone "
        "numbers, and more. Runs locally — no data leaves your machine."
    ),
)


@mcp.tool()
def datafog_scan(
    text: str,
    engine: str = "smart",
    entity_types: list[str] | None = None,
) -> dict[str, Any]:
    """Scan text for PII and return detected entities."""

    result = scan(text=text, engine=engine, entity_types=entity_types)
    return {
        "entity_count": len(result.entities),
        "entities": [
            {
                "type": entity.type,
                "text": entity.text,
                "start": entity.start,
                "end": entity.end,
                "confidence": entity.confidence,
            }
            for entity in result.entities
        ],
        "engine_used": result.engine_used,
    }


def run_server() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")
