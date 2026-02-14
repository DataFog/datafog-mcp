from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility fallback.
    import tomli as tomllib


DEFAULT_SERVER_CONFIG_PATH = "datafog-mcp.toml"


def _set_telemetry_env(no_telemetry: bool) -> None:
    os.environ["DATAFOG_NO_TELEMETRY"] = "1" if no_telemetry else "0"


def _normalize_entity_types(value: str | list[str] | None) -> list[str] | None:
    if value is None:
        return None

    if isinstance(value, list):
        return [item.strip() for item in value if str(item).strip()]

    if not isinstance(value, str):
        return None

    value = value.strip()
    if not value:
        return None

    return [item.strip() for item in value.split(",") if item.strip()]


def _coalesce(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _coerce_bool(value: str | bool | int | None) -> bool | None:
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return None


def _coalesce_bool(*values: Any) -> bool | None:
    for value in values:
        coerced = _coerce_bool(value)
        if coerced is not None:
            return coerced
    return None


def _coerce_int(value: int | str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _load_config_values(config_path: str | None, section: str) -> dict[str, Any]:
    if not config_path:
        return {}

    path = Path(config_path)
    if not path.exists():
        return {}

    raw = path.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    section_data = data.get(section, {})
    if not isinstance(section_data, dict):
        return {}
    return section_data


def _resolve_config_path(explicit_path: str | None) -> str | None:
    if explicit_path:
        return explicit_path

    default_path = Path(DEFAULT_SERVER_CONFIG_PATH)
    if default_path.exists():
        return str(default_path)

    return None


@dataclass
class ServerConfig:
    """Runtime configuration for Mode A tool server."""

    transport: str = "stdio"
    port: int = 8000
    engine: str = "smart"
    entity_types: list[str] | None = None
    strategy: str = "token"
    verbose: bool = False
    no_telemetry: bool = False
    log_redactions: bool = False
    config_path: str | None = None

    @classmethod
    def from_args(cls, args: Any) -> ServerConfig:
        config_path = _resolve_config_path(getattr(args, "config", None))
        config_file = _load_config_values(config_path, "server")

        cli_entity_types = _normalize_entity_types(getattr(args, "entities", None))
        env_entity_types = _normalize_entity_types(os.getenv("DATAFOG_ENTITY_TYPES"))

        file_entity_types = _normalize_entity_types(config_file.get("entity_types"))

        engine = _coalesce(
            getattr(args, "engine", None),
            os.getenv("DATAFOG_ENGINE"),
            config_file.get("engine"),
            cls().engine,
        )

        strategy = _coalesce(
            getattr(args, "strategy", None),
            os.getenv("DATAFOG_STRATEGY"),
            config_file.get("strategy"),
            cls().strategy,
        )

        verbose = _coalesce(
            getattr(args, "verbose", None),
            _coerce_bool(os.getenv("DATAFOG_VERBOSE")),
            config_file.get("verbose"),
            cls().verbose,
        )

        no_telemetry = _coalesce_bool(
            getattr(args, "no_telemetry", None),
            os.getenv("DATAFOG_NO_TELEMETRY"),
            cls().no_telemetry,
        )

        log_redactions = _coalesce_bool(
            getattr(args, "log_redactions", None),
            os.getenv("DATAFOG_LOG_REDACTIONS"),
            cls().log_redactions,
        )

        transport = _coalesce(
            getattr(args, "transport", None),
            config_file.get("transport"),
            cls().transport,
        )

        port = _coalesce(
            getattr(args, "port", None),
            config_file.get("port"),
            cls().port,
        )

        if isinstance(verbose, str):
            verbose = _coerce_bool(verbose)

        verbose = cls().verbose if verbose is None else bool(verbose)

        return cls(
            transport=transport or cls().transport,
            port=_coerce_int(port) or cls().port,
            engine=engine,
            entity_types=_coalesce(
                cli_entity_types,
                env_entity_types,
                file_entity_types,
                cls().entity_types,
            ),
            strategy=strategy,
            verbose=bool(verbose),
            no_telemetry=bool(no_telemetry),
            log_redactions=bool(log_redactions),
            config_path=config_path,
        )


@dataclass
class ProxyConfig:
    """Runtime configuration for Mode B proxy mode."""

    target_command: str | None = None
    target_args: list[str] | None = None
    engine: str = "smart"
    entity_types: list[str] | None = None
    strategy: str = "token"
    no_telemetry: bool = False
    log_redactions: bool = False
    config_path: str | None = None
    verbose: bool = False
    intercept_tool_arguments: bool = True
    intercept_tool_responses: bool = True
    intercept_resources: bool = False

    @classmethod
    def from_args(cls, args: Any) -> ProxyConfig:
        config_path = _resolve_config_path(getattr(args, "config", None))
        config_file = _load_config_values(config_path, "proxy")

        entities = _normalize_entity_types(getattr(args, "entities", None))
        env_entity_types = _normalize_entity_types(os.getenv("DATAFOG_ENTITY_TYPES"))
        file_entity_types = _normalize_entity_types(config_file.get("entity_types"))

        cli_wrap = getattr(args, "wrap", []) or []
        target_command = cli_wrap[0] if cli_wrap else None
        target_args = list(cli_wrap[1:]) if len(cli_wrap) > 1 else []

        engine = _coalesce(
            getattr(args, "engine", None),
            os.getenv("DATAFOG_ENGINE"),
            config_file.get("engine"),
            cls().engine,
        )

        strategy = _coalesce(
            getattr(args, "strategy", None),
            os.getenv("DATAFOG_STRATEGY"),
            config_file.get("strategy"),
            cls().strategy,
        )

        verbose = _coalesce(
            getattr(args, "verbose", None),
            _coerce_bool(os.getenv("DATAFOG_VERBOSE")),
            config_file.get("verbose"),
            cls().verbose,
        )

        verbose_bool = _coerce_bool(verbose)
        if verbose_bool is None:
            verbose_bool = cls().verbose

        no_telemetry = _coalesce_bool(
            getattr(args, "no_telemetry", None),
            os.getenv("DATAFOG_NO_TELEMETRY"),
            cls().no_telemetry,
        )

        log_redactions = _coalesce_bool(
            getattr(args, "log_redactions", None),
            os.getenv("DATAFOG_LOG_REDACTIONS"),
            cls().log_redactions,
        )

        intercept_tool_arguments = _coalesce_bool(
            getattr(args, "intercept_tool_arguments", None),
            os.getenv("DATAFOG_INTERCEPT_TOOL_ARGUMENTS"),
            config_file.get("intercept_tool_arguments"),
            cls().intercept_tool_arguments,
        )

        intercept_tool_responses = _coalesce_bool(
            getattr(args, "intercept_tool_responses", None),
            os.getenv("DATAFOG_INTERCEPT_TOOL_RESPONSES"),
            config_file.get("intercept_tool_responses"),
            cls().intercept_tool_responses,
        )

        intercept_resources = _coalesce_bool(
            getattr(args, "intercept_resources", None),
            os.getenv("DATAFOG_INTERCEPT_RESOURCES"),
            config_file.get("intercept_resources"),
            cls().intercept_resources,
        )

        return cls(
            target_command=target_command,
            target_args=target_args,
            engine=engine,
            entity_types=_coalesce(
                entities,
                env_entity_types,
                file_entity_types,
                cls().entity_types,
            ),
            strategy=strategy,
            config_path=config_path,
            verbose=verbose_bool,
            no_telemetry=bool(no_telemetry),
            log_redactions=bool(log_redactions),
            intercept_tool_arguments=bool(intercept_tool_arguments),
            intercept_tool_responses=bool(intercept_tool_responses),
            intercept_resources=bool(intercept_resources),
        )
