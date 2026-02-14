from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from datafog.engine import scan, scan_and_redact
from mcp.server.fastmcp import FastMCP

from .config import ServerConfig


mcp = FastMCP(
    name="datafog",
    instructions=(
        "PII detection and redaction tools. Scan text for emails, SSNs, names, "
        "phone numbers, and more. Runs locally — no data leaves your machine."
    ),
)


@dataclass(frozen=True)
class _ServerRuntime:
    config: ServerConfig = field(default_factory=ServerConfig)


_RUNTIME = _ServerRuntime()


def configure_server(config: ServerConfig) -> None:
    global _RUNTIME
    _RUNTIME = replace(_RUNTIME, config=config)


def _resolve_engine(engine: str | None) -> str:
    return engine or _RUNTIME.config.engine


def _resolve_entity_types(entity_types: list[str] | None) -> list[str] | None:
    if entity_types is not None:
        return entity_types
    return _RUNTIME.config.entity_types


def _resolve_strategy(strategy: str | None) -> str:
    return strategy or _RUNTIME.config.strategy


def _run_scan(text: str, *, engine: str | None, entity_types: list[str] | None) -> Any:
    return scan(
        text=text,
        engine=_resolve_engine(engine),
        entity_types=_resolve_entity_types(entity_types),
    )


def _run_scan_and_redact(
    text: str,
    *,
    engine: str | None,
    entity_types: list[str] | None,
    strategy: str | None,
) -> Any:
    return scan_and_redact(
        text=text,
        engine=_resolve_engine(engine),
        entity_types=_resolve_entity_types(entity_types),
        strategy=_resolve_strategy(strategy),
    )


@mcp.tool()
def datafog_scan(
    text: str,
    engine: str | None = None,
    entity_types: list[str] | None = None,
) -> dict[str, Any]:
    """Scan text for PII and return detected entities."""

    result = _run_scan(text=text, engine=engine, entity_types=entity_types)
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
    engine: str | None = None,
    entity_types: list[str] | None = None,
    strategy: str | None = None,
) -> dict[str, Any]:
    """Scan text for PII and redact it, returning cleaned text."""

    result = _run_scan_and_redact(
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
def datafog_restore(text: str, mapping: dict[str, str]) -> dict[str, str]:
    """Restore previously redacted PII using a token mapping."""

    restored = text
    for token, original in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        restored = restored.replace(token, original)
    return {"restored_text": restored}


def run_server(transport: str = "stdio", config: ServerConfig | None = None) -> None:
    if config is not None:
        configure_server(config)
        transport = config.transport
    if config is not None and transport == "streamable-http":
        mcp.run(transport=transport, port=config.port)
        return

    mcp.run(transport=transport)
