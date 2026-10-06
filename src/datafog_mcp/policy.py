"""Strict, immutable local policy snapshots. Never include policy values in errors."""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal, cast

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from datafog_mcp.config import SUPPORTED_ENTITIES

Action = Literal["ask", "transform", "proceed", "stop"]
TransformStrategy = Literal["redact", "mask", "remove", "pseudonymize"]
KeyBackend = Literal["keyring", "file"]


class PolicyError(ValueError):
    """Invalid or unreadable policy; message is safe to return to clients."""


@dataclass(frozen=True)
class PseudonymScope:
    key_ref: str
    backend: KeyBackend = "keyring"
    key_file: Path | None = None
    key_version: str = "1"


@dataclass(frozen=True)
class Policy:
    version: int = 1
    loaded: bool = False
    source_path: Path | None = None
    model_bundle_directory: Path | None = None
    model_timeout_seconds: int = 30
    model_join_person_gap: int = 0
    allow_exact: Mapping[str, tuple[str, ...]] = field(default_factory=lambda: MappingProxyType({}))
    output_directory: Path | None = None
    on_findings: Action = "ask"
    transform_strategy: TransformStrategy = "redact"
    transform_scope: str | None = None
    scope_folders: tuple[Path, ...] = ()
    scope_extensions: tuple[str, ...] = ()
    logging_enabled: bool = False
    log_path: Path = field(
        default_factory=lambda: Path.home() / ".local/state/datafog/activity.jsonl"
    )
    max_file_bytes: int = 100_000_000
    max_text_bytes: int = 1_048_576
    max_findings: int = 1000
    max_batch_files: int = 1000
    pseudonymization_scopes: Mapping[str, PseudonymScope] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        if type(self.model_join_person_gap) is not int or not 0 <= self.model_join_person_gap <= 3:
            raise PolicyError("Person composition gap must be an integer from 0 to 3.")
        # Copy nested collections as well, so callers cannot mutate a snapshot.
        object.__setattr__(
            self,
            "allow_exact",
            MappingProxyType({k: tuple(v) for k, v in self.allow_exact.items()}),
        )
        object.__setattr__(
            self, "pseudonymization_scopes", MappingProxyType(dict(self.pseudonymization_scopes))
        )


def _table(value: object, allowed: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise PolicyError("Policy sections must be tables.")
    if set(value) - allowed:
        raise PolicyError("Policy contains an unknown setting.")
    return cast(dict[str, object], value)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value):
        raise PolicyError("Policy lists must contain nonempty strings.")
    return tuple(cast(list[str], value))


def _string(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PolicyError("Policy setting requires a nonempty string.")
    return value


def _path(value: object) -> Path:
    path = Path(_string(value)).expanduser()
    if not path.is_absolute():
        raise PolicyError("Policy paths must be absolute or start with a home-directory reference.")
    return path


def _positive(value: object, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or value <= 0 or value > maximum:
        raise PolicyError("Policy limits must be positive integers within the supported range.")
    return value


def _choice(value: object, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise PolicyError("Policy contains an unsupported option.")
    return value


def _identifier(value: object) -> str:
    value = _string(value)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise PolicyError("Policy scope names and key references must be simple identifiers.")
    return value


def _parse(data: object, source_path: Path) -> Policy:
    root = _table(
        data,
        {
            "version",
            "allow",
            "output",
            "workflow",
            "scope",
            "logging",
            "limits",
            "pseudonymization",
            "model",
        },
    )
    if type(root.get("version")) is not int or root["version"] != 1:
        raise PolicyError("Policy must declare version = 1.")
    allow = _table(root.get("allow", {}), {"exact"})
    exact = _table(allow.get("exact", {}), set(SUPPORTED_ENTITIES) | {"PERSON", "STREET_ADDRESS"})
    allow_exact = {entity: _strings(values) for entity, values in exact.items()}
    output = _table(root.get("output", {}), {"directory"})
    workflow = _table(root.get("workflow", {}), {"on_findings", "transform_strategy", "scope"})
    scope = _table(root.get("scope", {}), {"folders", "extensions"})
    extensions = _strings(scope.get("extensions", []))
    if any(not re.fullmatch(r"\.[A-Za-z0-9]+", extension) for extension in extensions):
        raise PolicyError("Policy extensions must be dot-prefixed file extensions.")
    logging = _table(root.get("logging", {}), {"enabled", "path"})
    if type(logging.get("enabled", False)) is not bool:
        raise PolicyError("Policy logging enabled setting must be a boolean.")
    limits = _table(
        root.get("limits", {}),
        {"max_file_bytes", "max_text_bytes", "max_findings", "max_batch_files"},
    )
    model = _table(
        root.get("model", {}), {"bundle_directory", "timeout_seconds", "join_person_gap"}
    )
    pseudonymization = _table(root.get("pseudonymization", {}), {"scopes"})
    raw_scopes = pseudonymization.get("scopes", {})
    if not isinstance(raw_scopes, dict):
        raise PolicyError("Policy scopes must be a table.")
    scopes: dict[str, PseudonymScope] = {}
    for name, raw_scope in raw_scopes.items():
        name = _identifier(name)
        entry = _table(raw_scope, {"key_ref", "backend", "key_file", "key_version"})
        key_ref = _identifier(entry.get("key_ref"))
        backend = cast(KeyBackend, _choice(entry.get("backend", "keyring"), ("keyring", "file")))
        key_file = _path(entry["key_file"]) if "key_file" in entry else None
        if (backend == "file") != (key_file is not None):
            raise PolicyError("File key storage requires key_file; keyring storage must omit it.")
        scopes[name] = PseudonymScope(
            key_ref, backend, key_file, _identifier(entry.get("key_version", "1"))
        )
    strategy = cast(
        TransformStrategy,
        _choice(
            workflow.get("transform_strategy", "redact"),
            ("redact", "mask", "remove", "pseudonymize"),
        ),
    )
    transform_scope = _identifier(workflow["scope"]) if "scope" in workflow else None
    if transform_scope is not None and transform_scope not in scopes:
        raise PolicyError("Workflow references an unconfigured pseudonymization scope.")
    if strategy == "pseudonymize" and transform_scope is None:
        raise PolicyError("Pseudonymization workflow requires a configured scope.")
    if strategy != "pseudonymize" and transform_scope is not None:
        raise PolicyError("Workflow scope is only valid for pseudonymization.")
    defaults = Policy()
    return Policy(
        loaded=True,
        source_path=source_path,
        model_bundle_directory=_path(model["bundle_directory"])
        if "bundle_directory" in model
        else None,
        model_timeout_seconds=_positive(model.get("timeout_seconds", 30), 300),
        model_join_person_gap=cast(int, model.get("join_person_gap", 0)),
        allow_exact=allow_exact,
        output_directory=_path(output["directory"]) if "directory" in output else None,
        on_findings=cast(
            Action,
            _choice(workflow.get("on_findings", "ask"), ("ask", "transform", "proceed", "stop")),
        ),
        transform_strategy=strategy,
        transform_scope=transform_scope,
        scope_folders=tuple(_path(folder) for folder in _strings(scope.get("folders", []))),
        scope_extensions=tuple(extension.lower() for extension in extensions),
        logging_enabled=cast(bool, logging.get("enabled", False)),
        log_path=_path(logging["path"]) if "path" in logging else defaults.log_path,
        max_file_bytes=_positive(limits.get("max_file_bytes", defaults.max_file_bytes)),
        max_text_bytes=_positive(limits.get("max_text_bytes", defaults.max_text_bytes)),
        max_findings=_positive(limits.get("max_findings", defaults.max_findings), 100_000),
        max_batch_files=_positive(limits.get("max_batch_files", defaults.max_batch_files), 10_000),
        pseudonymization_scopes=scopes,
    )


def load_policy(path: Path | None = None) -> Policy:
    """Read one snapshot; subsequent calls reload. A missing optional file uses defaults.

    Policy paths are never resolved relative to the process working directory. This
    prevents launch location from changing the meaning of stored policy settings.
    """
    try:
        if path is None:
            override = os.environ.get("DATAFOG_POLICY_PATH")
            path = (
                _path(override)
                if override is not None
                else Path.home() / ".config/datafog/policy.toml"
            )
        path = _path(str(path))
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise PolicyError("Policy must be a regular file.")
            # Bound configuration parsing independently of input-file limits.
            raw = handle.read(1_048_577)
        if len(raw) > 1_048_576:
            raise PolicyError("Policy exceeds the configuration size limit.")
        return _parse(tomllib.loads(raw.decode("utf-8")), path)
    except FileNotFoundError:
        if path is not None and os.path.lexists(path):
            raise PolicyError("Policy exists but its target cannot be read.") from None
        return Policy(source_path=path)
    except PolicyError:
        raise
    except (OSError, UnicodeError, ValueError, RuntimeError):
        raise PolicyError(
            "Policy could not be read or parsed; check the local configuration."
        ) from None
