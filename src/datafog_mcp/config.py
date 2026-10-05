"""
Detection and transformation settings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from datafog_core import capabilities

if TYPE_CHECKING:
    from datafog_core import _TransformationConfig


def _text_scan_entities() -> frozenset[str]:
    """
    Ask the engine which types a plain text scan can report.

    Only default-activated, text-scoped types qualify. The server calls
    scan(text) with no config, so a type that needs a locale, a config flag,
    or structured input would never fire. Accepting one would let a caller
    request it and get an empty result reported as success.

    Returns:
      The entity types scan(text) can report.
    """
    return frozenset(
        name
        for name, capability in capabilities()["entities"].items()
        if capability["activation"]["kind"] == "default" and "text" in capability["scopes"]
    )


SUPPORTED_ENTITIES: frozenset[str] = _text_scan_entities()

# Which types are on by default is a product decision, so this stays
# explicit rather than following the engine's list. IP_ADDRESS is
# supported but opt-in.
DEFAULT_ENTITIES: tuple[str, ...] = (
    "API_KEY",
    "BEARER_TOKEN",
    "CREDENTIAL_URI",
    "CREDIT_CARD",
    "EMAIL",
    "JWT",
    "NPI",
    "PHONE",
    "PRIVATE_KEY",
    "SSN",
    "US_ROUTING_NUMBER",
)

Strategy = Literal["mask", "redact", "remove"]

DEFAULT_MAX_BYTES = 100_000_000


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
            raise ValueError(f"unsupported entity types: {', '.join(unsupported)}")
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


_STRATEGY_CONFIGS: dict[Strategy, _TransformationConfig] = {
    "mask": {"default": {"strategy": "mask"}},
    "redact": {"default": {"strategy": "redact"}},
    "remove": {"default": {"strategy": "remove"}},
}


def transform_config(strategy: Strategy) -> _TransformationConfig:
    """
    Look up the engine's transformation configuration.

    Built as literals rather than from the argument: core types each strategy
    as its own TypedDict, and a variable would stay a union that matches none
    of them.

    Parameters:
      strategy: One of mask, redact, or remove.
    Returns:
      The config datafog_core.transform expects.
    """
    return _STRATEGY_CONFIGS[strategy]
