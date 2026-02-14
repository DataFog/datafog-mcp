from __future__ import annotations

from collections.abc import ItemsView
from dataclasses import dataclass, field
from threading import Lock


def _sort_items_desc(items: ItemsView[str, str]) -> list[tuple[str, str]]:
    return sorted(items, key=lambda item: len(item[0]), reverse=True)


@dataclass
class TokenMapper:
    """Bidirectional token map for a proxy session."""

    _token_to_real: dict[str, str] = field(default_factory=dict)
    _real_to_token: dict[str, str] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def store(self, mapping: dict[str, str]) -> None:
        with self._lock:
            for token, real in mapping.items():
                self._token_to_real[token] = real
                self._real_to_token[real] = token

    def restore(self, text: str) -> str:
        restored = text
        with self._lock:
            for token, real in _sort_items_desc(self._token_to_real.items()):
                restored = restored.replace(token, real)
        return restored

    def redact(self, text: str) -> str:
        redacted = text
        with self._lock:
            for real, token in _sort_items_desc(self._real_to_token.items()):
                redacted = redacted.replace(real, token)
        return redacted

    def clear(self) -> None:
        with self._lock:
            self._token_to_real.clear()
            self._real_to_token.clear()

    @property
    def mapping_table(self) -> dict[str, str]:
        with self._lock:
            return dict(self._token_to_real)
