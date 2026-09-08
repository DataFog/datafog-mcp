"""
Detection and transformation settings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SUPPORTED_ENTITIES: frozenset[str] = frozenset(
    {
        "CREDIT_CARD",
        "DATE",
        "EMAIL",
        "IP_ADDRESS",
        "PHONE",
        "SSN",
        "ZIP_CODE",
    }
)

DEFAULT_ENTITIES: tuple[str, ...] = (
    "CREDIT_CARD",
    "DATE",
    "EMAIL",
    "PHONE",
    "SSN",
    "ZIP_CODE",
)

VALID_STRATEGIES: frozenset[str] = frozenset(
    {
        "mask",
        "redact",
        "remove",
    }
)

DEFAULT_MAX_BYTES = 1_048_576


@dataclass(frozen=True)
class ScanConfig:
    """
    Detection settings for a single request.
    """

    entities: tuple[str, ...] = DEFAULT_ENTITIES
    max_bytes: int = DEFAULT_MAX_BYTES

    def __post_init__(self) -> None:
        """
        Reject invalid settings at construction time.
        """
        if not self.entities:
            raise ValueError("entities must not be empty")
        unsupported = sorted(set(self.entities) - SUPPORTED_ENTITIES)
        if unsupported:
            raise ValueError(f"unsupported entity types: {','.join(unsupported)}")
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")

    def keeps(self, entity_type: str) -> bool:
        """
        Report whether a detected type was requested.

        Parameters:
          entity_type: The label carried by a finding.
        Returns:
          True when the caller asked for this type.
        """
        return entity_type in self.entities


def transform_config(strategy: str) -> dict[str, Any]:
    """
    Build the engine's transformation configuration.

    Parameters:
        strategy: One of mask, redact, or remove.
    Returns:
        The config dict datafog_core.transform expects.
    """
    if strategy not in VALID_STRATEGIES:
        raise ValueError(f"unsupported strategy: {strategy}")
    return {"default": {"strategy": strategy}}
