from __future__ import annotations

from dataclasses import dataclass

VALID_ENGINES: frozenset[str] = frozenset({"regex", "spacy", "gliner", "smart"})

DEFAULT_ENTITIES: tuple[str, ...] = (
    "EMAIL",
    "PHONE",
    "SSN",
    "CREDIT_CARD",
    "DOB",
    "ZIP",
)

NER_ENTITIES: frozenset[str] = frozenset({"PERSON", "ORGANIZATION", "LOCATION", "ADDRESS"})

DEFAULT_MAX_BYTES = 1_048_576


@dataclass(frozen=True)
class ScanConfig:
    """
    Detection settings for a single scan request.
    """

    engine: str = "regex"
    entities: tuple[str, ...] = DEFAULT_ENTITIES
    max_bytes: int = DEFAULT_MAX_BYTES
    allowlist: tuple[str, ...] = ()
    allowlist_patterns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """
        Reject invalid settings at construction time.
        """
        if self.engine not in VALID_ENGINES:
            raise ValueError("invalid engine")
        if not self.entities:
            # An empty list disables type filtering and makes the engine attempt NER on every call
            raise ValueError("entities must not be empty")
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")

    @property
    def requires_ner(self) -> tuple[str, ...]:
        """
        Requested entity types that depend on optional NER backends.

        Parameters: None
        Returns:
          The requested types that will yield nothing unless datafog[nlp] or
          datafog[nlp-advanced] is installed.
        """
        return tuple(e for e in self.entities if e in NER_ENTITIES)
