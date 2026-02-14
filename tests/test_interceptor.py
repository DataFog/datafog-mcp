from __future__ import annotations

import asyncio
from types import SimpleNamespace

from datafog_mcp import interceptor
from datafog_mcp.interceptor import (
    InterceptorConfig,
    is_candidate_text,
    restore_object_payload,
    restore_text,
    scan_and_replace_text,
)
from datafog_mcp.mapper import TokenMapper


def test_is_candidate_text() -> None:
    assert is_candidate_text("abc") is True
    assert is_candidate_text("") is False
    assert is_candidate_text(None) is False
    assert is_candidate_text(123) is False


def test_restore_object_payload_nested_data() -> None:
    mapper = TokenMapper()
    mapper.store({"[EMAIL_1]": "alice@example.com", "[PHONE_1]": "+15550001111"})

    payload = {
        "user": "[EMAIL_1]",
        "contacts": ["[PHONE_1]", {"alias": "[EMAIL_1]"}],
    }

    restored = restore_object_payload(payload, mapper)
    assert restored == {
        "user": "alice@example.com",
        "contacts": ["+15550001111", {"alias": "alice@example.com"}],
    }


def test_restore_object_payload_respects_intercept_toggle() -> None:
    mapper = TokenMapper()
    mapper.store({"[EMAIL_1]": "alice@example.com"})

    payload = {"user": "[EMAIL_1]"}
    restored = restore_object_payload(payload, mapper, intercept_tool_arguments=False)

    assert restored == payload


def test_restore_text_honors_mapper() -> None:
    mapper = TokenMapper()
    mapper.store({"[EMAIL_1]": "alice@example.com"})

    assert restore_text("user=[EMAIL_1]", mapper) == "user=alice@example.com"


def test_scan_and_replace_text_stores_mapping(monkeypatch: object) -> None:
    def fake_scan_and_redact(
        text: str,
        *,
        engine: str,
        entity_types: list[str] | None,
        strategy: str,
    ):
        return SimpleNamespace(
            redacted_text="[EMAIL_1]",
            mapping={"[EMAIL_1]": "alice@example.com"},
        )

    mapper = TokenMapper()
    config = InterceptorConfig()

    async def run() -> None:
        redacted = await scan_and_replace_text("alice@example.com", mapper, config)
        assert redacted == "[EMAIL_1]"
        assert mapper.mapping_table == {"[EMAIL_1]": "alice@example.com"}

    monkeypatch.setattr(interceptor, "scan_and_redact", fake_scan_and_redact)
    asyncio.run(run())
