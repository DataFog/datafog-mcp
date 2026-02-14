from __future__ import annotations

from datafog_mcp.mapper import TokenMapper


def test_store_and_restore_redact_round_trip() -> None:
    mapper = TokenMapper()
    mapper.store({"[EMAIL_1]": "a@x.com", "[PHONE_1]": "+15550001111"})

    assert mapper.restore("Contact [EMAIL_1]") == "Contact a@x.com"
    assert mapper.redact("Contact a@x.com") == "Contact [EMAIL_1]"


def test_store_is_deterministic_for_overlapping_tokens() -> None:
    mapper = TokenMapper()
    mapper.store({"[TOK_1]": "abc", "[TOK]": "long"})

    restored = mapper.restore("A [TOK_1] and [TOK]")
    assert restored == "A abc and long"


def test_clear_resets_state() -> None:
    mapper = TokenMapper()
    mapper.store({"[EMAIL_1]": "x"})
    mapper.clear()

    assert mapper.mapping_table == {}
    assert mapper.restore("[EMAIL_1]") == "[EMAIL_1]"
