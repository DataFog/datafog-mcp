"""Tests for datafog_mcp.config."""

from __future__ import annotations

import pytest

from datafog_mcp.config import (
    DEFAULT_ENTITIES,
    SUPPORTED_ENTITIES,
    ScanConfig,
    Strategy,
    transform_config,
)


def test_defaults_are_supported() -> None:
    """
    Every default entity is one the engine can detect.

    Would have caught the ZIP/ZIP_CODE rename slipping through.
    """
    assert set(DEFAULT_ENTITIES) <= SUPPORTED_ENTITIES


def test_default_config_constructs() -> None:
    """The zero-argument config is valid."""
    config = ScanConfig()

    assert config.entities == DEFAULT_ENTITIES
    assert config.max_bytes > 0


def test_empty_entities_are_rejected() -> None:
    """An empty selection is caller error, not detect-nothing."""
    with pytest.raises(ValueError, match="must not be empty"):
        ScanConfig(entities=())


def test_unsupported_entities_are_refused_without_repeating_them() -> None:
    """
    Unsupported types fail at construction, and the message lists what is allowed.

    Previously an unsupported type returned zero findings and reported
    success, so a caller could not tell "no PII" from "cannot detect."
    The rejected names are caller-supplied text, which could be anything, so
    the message holds the allowed values only.
    """
    with pytest.raises(ValueError) as refused:
        ScanConfig(entities=("EMAIL", "SECRET", "PERSON", "avery@example.com"))

    message = str(refused.value)
    assert message == (
        "unsupported entity type; each must be one of: " + ", ".join(sorted(SUPPORTED_ENTITIES))
    )
    for rejected in ("SECRET", "PERSON", "avery", "example.com"):
        assert rejected not in message
        assert rejected not in repr(refused.value)


@pytest.mark.parametrize("entity", ["PERSON", "UUID", "DE_IBAN"])
def test_types_a_text_scan_cannot_report_are_unsupported(entity: str) -> None:
    """
    Types the engine knows but a plain text scan never reports are refused.

    PERSON needs structured input, UUID a config flag, and DE_IBAN a locale.
    The server passes none of these, so accepting them would return an empty
    result reported as success.

    Parameters:
      entity: A type core lists but scan(text) cannot report.
    """
    assert entity not in SUPPORTED_ENTITIES


def test_non_positive_max_bytes_is_rejected() -> None:
    """A zero or negative cap would refuse every file."""
    with pytest.raises(ValueError, match="max_bytes must be positive"):
        ScanConfig(max_bytes=0)


def test_keeps_reflects_the_selection() -> None:
    """keeps answers for the requested types only."""
    config = ScanConfig(entities=("EMAIL",))

    assert config.keeps("EMAIL")
    assert not config.keeps("PHONE")


@pytest.mark.parametrize("strategy", ["mask", "redact", "remove"])
def test_transform_config_names_the_strategy(strategy: Strategy) -> None:
    """Each strategy maps to the engine's config shape."""
    assert transform_config(strategy) == {"default": {"strategy": strategy}}
