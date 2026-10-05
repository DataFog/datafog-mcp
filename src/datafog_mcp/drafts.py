"""Validate draft arguments before framework validation can log their values."""

from __future__ import annotations

from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult
from mcp.types import CallToolRequestParams

from .config import DEFAULT_MAX_BYTES, SUPPORTED_ENTITIES


def validate_draft(arguments: dict[str, Any]) -> None:
    """Refuse malformed, non-UTF-8, or oversized drafts with fixed messages."""
    if set(arguments) - {"text", "entity_types"}:
        raise ToolError("Draft checks accept only text and entity_types.")
    text = arguments.get("text")
    if not isinstance(text, str):
        raise ToolError("Draft text must be a string.")
    # A character needs at least one UTF-8 byte. Bound allocation before encoding.
    if len(text) > DEFAULT_MAX_BYTES:
        raise ToolError("Draft text exceeds the 1 MiB UTF-8 byte limit.")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise ToolError("Draft text must be valid UTF-8.") from None
    if size > DEFAULT_MAX_BYTES:
        raise ToolError("Draft text exceeds the 1 MiB UTF-8 byte limit.")
    selected = arguments.get("entity_types")
    if selected is not None and (
        not isinstance(selected, list)
        or not selected
        or any(not isinstance(kind, str) or kind not in SUPPORTED_ENTITIES for kind in selected)
    ):
        raise ToolError("entity_types must be a nonempty list of supported entity types.")


class DraftValidationMiddleware(Middleware):
    """Keep draft values out of FastMCP's argument-validation warning logs."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        if context.message.name == "datafog_check_text":
            validate_draft(context.message.arguments or {})
        return await call_next(context)
