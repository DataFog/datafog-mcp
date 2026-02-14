from __future__ import annotations

from datafog.engine import scan, scan_and_redact
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="datafog",
    version="0.1.0",
    description="PII detection and redaction tools. Scan text for emails, SSNs, names, phone numbers, and more. Runs locally — no data leaves your machine.",
)


@mcp.tool()
def datafog_scan(
    text: str,
    engine: str = "smart",
    entity_types: list[str] | None = None,
) -> dict:
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


@mcp.tool()
def datafog_redact(
    text: str,
    engine: str = "smart",
    entity_types: list[str] | None = None,
    strategy: str = "token",
) -> dict:
    """Scan text for PII and redact it, returning cleaned text."""

    result = scan_and_redact(
        text=text,
        engine=engine,
        entity_types=entity_types,
        strategy=strategy,
    )

    return {
        "redacted_text": result.redacted_text,
        "mapping": result.mapping,
        "entity_count": len(result.entities),
    }


@mcp.tool()
def datafog_restore(text: str, mapping: dict[str, str]) -> dict:
    """Restore previously redacted PII using a token mapping."""

    restored = text
    for token, original in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        restored = restored.replace(token, original)
    return {"restored_text": restored}


def run_server(transport: str = "stdio") -> None:
    mcp.run(transport=transport)
