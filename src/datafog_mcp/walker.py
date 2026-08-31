"""
Extract and rewrite the scannable strings inside a tool payload.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

MAX_SCAN_CHARS = 1_000_000
TOTAL_SCAN_CHARS = 8_000_000

# Temporary workaround for upstream engine regex boundary issues
# If fixed, then can remove this
SLACK_SKIP_KEYS: frozenset[str] = frozenset(
    {
        "channel_actions_ts",
        "thread_ts",
        "ts",
    }
)


@dataclass
class ScanBudget:
    """
    Cap how much text one tool result might hand to the scanner.
    """
    per_string: int = MAX_SCAN_CHARS
    total: int = TOTAL_SCAN_CHARS
    used: int = 0
    exhausted: bool = False

    def claim(self, text: str) -> bool:
        """
        Reserve budget for one string.

        Parameters:
          text: The string about to be scanned.
        Returns:
          True if the string fits within both caps.
        """
        size = len(text)
        if size > self.per_string or self.used + size > self.total:
            self.exhausted = True
            return False
        self.used += size
        return True


def transform_strings(
        data: Any,
        fn: Callable[[str], str],
        budget: ScanBudget,
        skip_keys: frozenset[str] = frozenset(),
) -> Any:
    """
    Apply fn to every scannable string in a parsed JSON structure.

    Walks with an explicit stack so that deeply nested payloads cannot raise
    RecursionError and leave a result silently unscanned. Mutates data in place, 
    so pass a freshly parsed structure.

    Parameters:
      data: A dict or list parsed from JSON.
      fn: Called with each scannable string; returns its placement.
      budget: Character caps, updated as strings are visited.
      skip_keys: Object keys whose values are structural identifiers.
    Returns:
      The same structure, with scannable strings replaced.
    """
    stack: list[Any] = [data]

    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key in skip_keys:
                    continue
                if isinstance(value, str):
                    if budget.claim(value):
                        node[key] = fn(value)
                elif isinstance(value, (dict, list)):
                    stack.append(value)

        elif isinstance(node, list):
            for index, value in enumerate(node):
                if isinstance(value, str):
                    if budget.claim(value):
                        node[index] = fn(value)
                elif isinstance(value, (dict, list)):
                    stack.append(value)

    return data


def transform_text(
        text: str,
        fn: Callable[[str], str],
        budget: ScanBudget,
        skip_keys: frozenset[str] = frozenset(),
) -> str:
    """
    Apply fn inside a text block, respecting JSON structure if present.

    A server that declares no output schema returns its whole payload as one 
    JSON string. Scanning that string flat lets matches run across delimiters 
    and defeats skip_keys, so parse it first.

    Parameters:
      text: One text block from a tool result.
      fn: Called with each scannable string; returns its replacement.
      budget: Character caps, updated as strings are visited.
      skip_keys: Object keys whose values are structural identifiers.
    Returns:
      The text with scannable strings replaced, or the original text
      unchanged when fn replaced nothing.
    """
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return fn(text) if budget.claim(text) else text

    if not isinstance(parsed, (dict, list)):
        return fn(text) if budget.claim(text) else text

    changed = False

    def _track(value: str) -> str:
        """
        Apply fn and record whether it altered the value.

        Parameters:
          value: The string handed to fn.
        Returns:
          The replacement fn produced.
        """
        nonlocal changed
        replacement = fn(value)
        changed = changed or replacement != value
        return replacement

    transform_strings(parsed, _track, budget, skip_keys)

    if not changed:
        return text
    return json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)