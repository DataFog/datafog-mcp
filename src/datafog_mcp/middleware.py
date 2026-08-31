"""
Scan and redact tool results as they pass through the proxy.
"""

from __future__ import annotations

import logging

import mcp.types as mt
from datafog import engine
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from .config import ScanConfig
from .findings import counts_by_type
from .walker import ScanBudget, transform_strings, transform_text

logger = logging.getLogger(__name__)

# v1 ships the irreversible operations only. The engine also accepts "hash" and
# "pseudonymize", but both are out of scope for v1
VALID_STRATEGIES: frozenset[str] = frozenset({"mask", "token"})


class _Redactor:
    """
    Hand each string to the engine and keep a tally of what it found.
    """

    def __init__(self, config: ScanConfig, strategy: str) -> None:
        """
        Parameters:
          config: Detection settings for this call.
          strategy: Either "mask" or "token".
        Returns:
          None.
        """
        if strategy not in VALID_STRATEGIES:
            raise ValueError("strategy must be mask or token")
        self._config = config
        self._strategy = strategy
        self.counts: dict[str, int] = {}

    def __call__(self, value: str) -> str:
        """
        Redact one string.

        RedactResult.mapping holds plaintext under every strategy and is
        deliberately not read.

        Parameters:
          value: A string taken from the tool result.
        Returns:
          The string as the engine redacted it.
        """
        result = engine.scan_and_redact(
            value,
            engine=self._config.engine,
            entity_types=list(self._config.entities),
            strategy=self._strategy,
            allowlist=list(self._config.allowlist) or None,
            allowlist_patterns=list(self._config.allowlist_patterns) or None,
        )

        for name, count in counts_by_type(result.entities).items():
            self.counts[name] = self.counts.get(name, 0) + count

        return result.redacted_text


class RedactingMiddleware(Middleware):
    """
    Redact detections from every tool result the proxy returns.
    """

    def __init__(
        self,
        config: ScanConfig | None = None,
        strategy: str = "mask",
        skip_keys: frozenset[str] = frozenset(),
    ) -> None:
        """
        Parameters:
          config: Detection settings; defaults to ScanConfig().
          strategy: Either "mask" or "token".
          skip_keys: Payload keys holding structural identifiers.
        Returns:
          None.
        """
        self._config = config or ScanConfig()
        self._strategy = strategy
        self._skip_keys = skip_keys

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """
        Scan the wrapped server's response before the client sees it.

        Parameters:
          context: The in-flight tool call.
          call_next: Invokes the wrapped server.
        Returns:
          The result with detections replaced, or an error result when
          the payload was too large to scan completely.
        """
        result = await call_next(context)

        budget = ScanBudget()
        redactor = _Redactor(self._config, self._strategy)

        content = [
            block.model_copy(
                update={"text": transform_text(block.text, redactor, budget, self._skip_keys)}
            )
            if isinstance(block, mt.TextContent)
            else block
            for block in result.content
        ]

        structured = result.structured_content
        if isinstance(structured, dict):
            structured = transform_strings(structured, redactor, budget, self._skip_keys)

        tool = context.message.name

        if budget.exhausted:
            logger.warning("datafog: withheld %s, exceeded scan budget", tool)
            return ToolResult(
                content=[
                    mt.TextContent(
                        type="text",
                        text=("datafog: this response was too large to scan and was withheld."),
                    )
                ],
                is_error=True,
            )

        if redactor.counts:
            summary = ", ".join(
                f"{name} x{count}" for name, count in sorted(redactor.counts.items())
            )
            logger.info("datafog: %s %s", tool, summary)

        return ToolResult(
            content=content,
            structured_content=structured,
            meta=result.meta,
            is_error=result.is_error,
        )
