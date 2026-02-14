from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ProxyConfig:
    """Runtime configuration shared by server and proxy modes."""

    target_command: str | None = None
    target_args: list[str] | None = None
    engine: str = "smart"
    entity_types: list[str] | None = None
    strategy: str = "token"
    config_path: str | None = None
    verbose: bool = False

    @classmethod
    def from_args(cls, args: Any) -> "ProxyConfig":
        entities = getattr(args, "entities", None)
        entity_types = None
        if entities:
            entity_types = [item.strip() for item in entities.split(",") if item.strip()]

        wrap = getattr(args, "wrap", []) or []
        target_command = wrap[0] if wrap else None
        target_args = list(wrap[1:]) if len(wrap) > 1 else []

        return cls(
            target_command=target_command,
            target_args=target_args,
            engine=getattr(args, "engine", "smart"),
            entity_types=entity_types,
            strategy=getattr(args, "strategy", "token"),
            config_path=getattr(args, "config", None),
            verbose=bool(getattr(args, "verbose", False)),
        )
