"""
Tests for the tool-payload walker.
"""

from __future__ import annotations

import json
from pathlib import Path

from datafog_mcp.walker import SLACK_SKIP_KEYS, ScanBudget, transform_text

FIXTURE = Path(__file__).parent / "fixtures" / "slack_history.json"

EMAIL = "jack.smith@example.com"
PHONE_BARE = "4155550182"
PHONE_DASHED = "415-555-0182"
MESSAGE_COUNT = 13


def _payload() -> str:
    """
    Read the captured Slack payload.

    Returns:
      The raw JSON text exactly as the server returned it.
    """
    return FIXTURE.read_text(encoding="utf-8")


def _collect(text: str, skip_keys: frozenset[str]) -> list[str]:
    """
    Record every string the walker offers to the scanner.

    Parameters:
      text: The payload to walk.
      skip_keys: Keys the walker should not scan.
    Returns:
      The strings passed to the transform function, in visit order.
    """
    seen: list[str] = []

    def _record(value: str) -> str:
        """
        Note one string and leave it untouched.

        Parameters:
          value: The string offered by the walker.
        Returns:
          The same string.
        """
        seen.append(value)
        return value

    transform_text(text, _record, ScanBudget(), skip_keys)
    return seen


def _timestamps() -> list[str]:
    """
    Every message timestamp in the captured payload.

    Returns:
      The ts value of each message.
    """
    messages = json.loads(_payload())["messages"]
    return [message["ts"] for message in messages]


def test_contact_details_reach_the_scanner() -> None:
    """
    Every occurrence of the email and phone is offered for scanning.
    """
    joined = "\n".join(_collect(_payload(), SLACK_SKIP_KEYS))

    assert joined.count(EMAIL) == 4
    assert joined.count(PHONE_BARE) == 2
    assert joined.count(PHONE_DASHED) == 2


def test_skip_keys_withhold_timestamps() -> None:
    """
    No timestamp is offered to the scanner when its key is skipped.
    """
    seen = _collect(_payload(), SLACK_SKIP_KEYS)

    assert set(_timestamps()).isdisjoint(seen)


def test_timestamps_are_scanned_without_skip_keys() -> None:
    """
    Every timestamp reaches the scanner by default, which is what
    produces the PHONE false positives.
    """
    timestamps = _timestamps()
    seen = _collect(_payload(), frozenset())

    assert len(timestamps) == MESSAGE_COUNT
    assert set(timestamps) <= set(seen)


def test_unchanged_payload_is_returned_verbatim() -> None:
    """
    A payload with nothing replaced is not re-serialized.
    """
    text = _payload()

    assert transform_text(text, lambda value: value, ScanBudget()) == text


def test_oversized_string_marks_budget_exhausted() -> None:
    """
    A string past the per-string cap is left alone and flagged.
    """
    budget = ScanBudget(per_string=8)
    text = json.dumps({"text": "a much longer string than eight"})

    result = transform_text(text, lambda value: "REDACTED", budget)

    assert budget.exhausted
    assert result == text