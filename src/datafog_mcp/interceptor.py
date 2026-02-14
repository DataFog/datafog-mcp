from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from datafog.engine import scan_and_redact

from .mapper import TokenMapper


@dataclass(frozen=True)
class InterceptorConfig:
    engine: str = "smart"
    entity_types: list[str] | None = None
    strategy: str = "token"
    intercept_tool_arguments: bool = True
    intercept_tool_responses: bool = True
    intercept_resources: bool = False


async def scan_and_replace_text(text: str, mapper: TokenMapper, config: InterceptorConfig) -> str:
    """Scan text with DataFog and return redacted text.

    Runs in a worker thread to avoid blocking the event loop for CPU-bound scan.
    """

    result = await asyncio.to_thread(
        scan_and_redact,
        text=text,
        engine=config.engine,
        entity_types=config.entity_types,
        strategy=config.strategy,
    )
    mapper.store(result.mapping)
    return result.redacted_text


def restore_text(text: str, mapper: TokenMapper) -> str:
    return mapper.restore(text)


def is_resource_text(value: str) -> bool:
    normalized = value.strip()
    if not normalized:
        return False

    lower = normalized.lower()
    return (
        lower.startswith("http://")
        or lower.startswith("https://")
        or lower.startswith("file://")
        or lower.startswith("ftp://")
        or lower.startswith("s3://")
    )


def is_candidate_text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def restore_object_payload(
    payload: Any,
    mapper: TokenMapper,
    intercept_tool_arguments: bool = True,
) -> Any:
    if not intercept_tool_arguments:
        return payload

    if isinstance(payload, str):
        return restore_text(payload, mapper)
    if isinstance(payload, list):
        return [
            restore_object_payload(
                item,
                mapper,
                intercept_tool_arguments=intercept_tool_arguments,
            )
            for item in payload
        ]
    if isinstance(payload, dict):
        return {
            key: restore_object_payload(
                value,
                mapper,
                intercept_tool_arguments=intercept_tool_arguments,
            )
            for key, value in payload.items()
        }
    return payload
