from __future__ import annotations

from types import SimpleNamespace

from datafog_mcp.config import ServerConfig
from datafog_mcp import server


def test_datafog_scan_uses_default_server_config(monkeypatch: object) -> None:
    called = {}

    def fake_scan(text: str, *, engine: str = "smart", entity_types: list[str] | None = None):
        called["text"] = text
        called["engine"] = engine
        called["entity_types"] = entity_types
        return SimpleNamespace(
            entities=[
                SimpleNamespace(
                    type="EMAIL",
                    text="jane@example.com",
                    start=0,
                    end=16,
                    confidence=0.99,
                )
            ],
            engine_used=engine,
        )

    monkeypatch.setattr(server, "scan", fake_scan)

    server.configure_server(ServerConfig(engine="smart", entity_types=["EMAIL", "PHONE"]))
    result = server.datafog_scan("please redact jane@example.com")

    assert result["entity_count"] == 1
    assert result["engine_used"] == "smart"
    assert result["entities"][0]["type"] == "EMAIL"
    assert called["engine"] == "smart"
    assert called["entity_types"] == ["EMAIL", "PHONE"]


def test_datafog_scan_respects_explicit_args(monkeypatch: object) -> None:
    called = {}

    def fake_scan(text: str, *, engine: str = "smart", entity_types: list[str] | None = None):
        called["engine"] = engine
        called["entity_types"] = entity_types
        return SimpleNamespace(entities=[], engine_used=engine)

    monkeypatch.setattr(server, "scan", fake_scan)

    server.configure_server(ServerConfig(engine="smart", entity_types=["EMAIL"]))
    server.datafog_scan("text", engine="regex", entity_types=["SSN"])

    assert called["engine"] == "regex"
    assert called["entity_types"] == ["SSN"]


def test_datafog_redact_uses_default_strategy(monkeypatch: object) -> None:
    def fake_scan_and_redact(
        text: str,
        *,
        engine: str = "smart",
        entity_types: list[str] | None = None,
        strategy: str = "token",
    ):
        return SimpleNamespace(
            redacted_text="[EMAIL_1]",
            mapping={"[EMAIL_1]": "alice@example.com"},
            entities=[
                SimpleNamespace(
                    type="EMAIL",
                    text="alice@example.com",
                    start=0,
                    end=16,
                    confidence=0.99,
                )
            ],
            engine_used=engine,
        )

    monkeypatch.setattr(server, "scan_and_redact", fake_scan_and_redact)

    server.configure_server(ServerConfig(strategy="token"))
    result = server.datafog_redact("alice@example.com")

    assert result["redacted_text"] == "[EMAIL_1]"
    assert result["mapping"] == {"[EMAIL_1]": "alice@example.com"}
    assert result["entity_count"] == 1


def test_datafog_restore_replaces_longest_tokens_first() -> None:
    result = server.datafog_restore(
        text="Found [EMAIL_1] and [EMAIL_10]",
        mapping={"[EMAIL_1]": "a", "[EMAIL_10]": "b"},
    )

    assert result["restored_text"] == "Found a and b"
