"""Owner-configured policy snapshots, reloaded and validated for each request."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal, cast

from .config import SUPPORTED_ENTITIES

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

POLICY_FILE = Path.home() / ".config" / "datafog" / "policy.toml"
POLICY_TEMPLATE = """\
# Owner privacy workflow settings. Copies stay beside the input by default.
version = 1

# To choose one output directory, create it, allow it in your roots policy,
# and uncomment these lines with your directory:
# [output]
# directory = "~/Documents/datafog-copies"
#
# [allow.exact]
# EMAIL = ["public-support@example.com"]
#
# [scope]
# folders = ["~/Downloads/customer-exports"]
# extensions = [".csv", ".tsv"]
#
# [workflow]
# on_findings = "ask"  # ask, transform, or stop (agent guidance)
# transform_strategy = "redact"  # redact, mask, remove, or pseudonymize
# pseudonym_scope = "customers"  # required for pseudonymize
#
# [pseudonymization.scopes.customers]
# key_ref = "customers"
# key_version = "1"
# backend = "keyring"  # OS credential storage; explicit "file" for headless POSIX
# key_file = "/absolute/private/customers.key"  # file backend only
#
# [model]
# bundle_directory = "/absolute/path/from/model-install"
# timeout_seconds = 30  # inference, including waiting and segmentation
#
# [activity]
# enabled = true  # off by default; metadata only, best effort
# path = "~/.local/share/datafog/activity/activity.jsonl"
# Run `datafog-mcp activity init` after creating its private parent directory.
"""

Action = Literal["ask", "transform", "stop"]


@dataclass(frozen=True)
class ModelPolicy:
    """An explicitly installed local model bundle, never a download instruction."""

    bundle_directory: Path
    timeout_seconds: float = 30


@dataclass(frozen=True)
class ActivityPolicy:
    """Explicit local metadata logging, independent of successful tool operations."""

    enabled: bool = False
    path: Path | None = None


WriteStrategy = Literal["redact", "mask", "remove", "pseudonymize"]


@dataclass(frozen=True)
class PseudonymScope:
    """A local key reference, never raw key material."""

    key_ref: str
    backend: Literal["keyring", "file"] = "keyring"
    key_file: Path | None = None
    key_version: str = "1"


class OutputPolicyError(ValueError):
    """An unusable policy; its message never includes policy values."""


@dataclass(frozen=True)
class OutputPolicy:
    """Immutable owner settings, including the fixed copy destination."""

    directory: Path | None = None
    allow_exact: Mapping[str, frozenset[str]] = field(default_factory=lambda: MappingProxyType({}))
    scope_folders: tuple[Path, ...] = ()
    scope_extensions: tuple[str, ...] = ()
    on_findings: Action = "ask"
    transform_strategy: WriteStrategy = "redact"
    pseudonym_scope: str | None = None
    pseudonym_scopes: Mapping[str, PseudonymScope] = field(default_factory=dict)
    model: ModelPolicy | None = None
    activity: ActivityPolicy = field(default_factory=ActivityPolicy)

    def __post_init__(self) -> None:
        object.__setattr__(self, "pseudonym_scopes", MappingProxyType(dict(self.pseudonym_scopes)))
        object.__setattr__(
            self,
            "allow_exact",
            MappingProxyType(
                {kind: frozenset(values) for kind, values in self.allow_exact.items()}
            ),
        )

    def is_allowlisted(self, entity_type: str, value: str) -> bool:
        """Match an owner-approved value exactly and only for its entity type."""
        return value in self.allow_exact.get(entity_type, frozenset())

    def in_scope(self, path: Path) -> bool:
        """Test advisory scope; callers must enforce roots separately first."""
        folder_match = not self.scope_folders or any(
            path == folder or folder in path.parents for folder in self.scope_folders
        )
        extension_match = (
            not self.scope_extensions or path.suffix.casefold() in self.scope_extensions
        )
        return folder_match and extension_match


def _table(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - keys:
        raise OutputPolicyError("policy contains an unknown setting or invalid table")
    return cast(dict[str, object], value)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item or "\x00" in item for item in value
    ):
        raise OutputPolicyError("policy lists must contain nonempty strings")
    return tuple(cast(list[str], value))


def _scope_paths(value: object) -> tuple[Path, ...]:
    # Import here: the path access layer also loads this policy for writes.
    from .paths import DENIED_DIR_NAMES, PathNotAllowed, allowed_roots

    try:
        roots = allowed_roots()
    except PathNotAllowed:
        raise OutputPolicyError("allowed roots cannot be used to validate scanning scope") from None
    folders: list[Path] = []
    for raw in _strings(value):
        try:
            folder = Path(raw).expanduser()
            if not folder.is_absolute():
                raise OutputPolicyError("scanning scope folders must be absolute or start with ~")
            folder = folder.resolve(strict=True)
            if not folder.is_dir():
                raise OutputPolicyError("scanning scope folders must already exist as directories")
        except (OSError, RuntimeError):
            raise OutputPolicyError("scanning scope folder cannot be resolved") from None
        if any(part.casefold() in DENIED_DIR_NAMES for part in folder.parts):
            raise OutputPolicyError("scanning scope folder is in a refused credential directory")
        if not any(folder == root or root in folder.parents for root in roots):
            raise OutputPolicyError("scanning scope folder is outside allowed roots")
        folders.append(folder)
    return tuple(folders)


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise OutputPolicyError("invalid pseudonymization identifier")
    return value


def _pseudonym_scopes(value: object) -> dict[str, PseudonymScope]:
    settings = _table(value, {"scopes"})
    raw_scopes = settings.get("scopes", {})
    if not isinstance(raw_scopes, dict):
        raise OutputPolicyError("pseudonymization scopes must be a table")
    result: dict[str, PseudonymScope] = {}
    for name, raw in raw_scopes.items():
        _identifier(name)
        entry = _table(raw, {"key_ref", "key_version", "backend", "key_file"})
        ref = _identifier(entry.get("key_ref"))
        version = _identifier(entry.get("key_version", "1"))
        backend = entry.get("backend", "keyring")
        if backend not in ("keyring", "file"):
            raise OutputPolicyError("pseudonymization backend must be keyring or file")
        key_file = None
        if backend == "file":
            raw_path = entry.get("key_file")
            if (
                os.name != "posix"
                or not isinstance(raw_path, str)
                or not raw_path
                or "\x00" in raw_path
            ):
                raise OutputPolicyError("file keys require a configured POSIX path")
            try:
                key_file = Path(raw_path).expanduser()
            except RuntimeError:
                raise OutputPolicyError("key file cannot be expanded") from None
            if not key_file.is_absolute() or ".." in key_file.parts:
                raise OutputPolicyError("key files require absolute paths without parent traversal")
        elif "key_file" in entry:
            raise OutputPolicyError("key_file is only valid for the explicit file backend")
        result[name] = PseudonymScope(ref, backend, key_file, version)
    return result


def load_output_policy() -> OutputPolicy:
    """Load a strict version-1 policy; only an absent file uses the default."""
    if not os.path.lexists(POLICY_FILE):
        return OutputPolicy()
    if not POLICY_FILE.is_file():
        raise OutputPolicyError("output policy is not a regular file")
    try:
        with POLICY_FILE.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        raise OutputPolicyError("cannot read output policy as valid UTF-8 TOML") from None
    if set(data) - {
        "version",
        "output",
        "allow",
        "scope",
        "workflow",
        "pseudonymization",
        "model",
        "activity",
    }:
        raise OutputPolicyError("output policy contains an unknown setting")
    if type(data.get("version")) is not int or data["version"] != 1:
        raise OutputPolicyError("output policy must declare version = 1")
    output = _table(data.get("output", {}), {"directory"})
    directory = None
    if "directory" in output:
        raw = output["directory"]
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise OutputPolicyError("output directory must be a nonempty absolute path")
        try:
            directory = Path(raw).expanduser()
            if not directory.is_absolute():
                raise OutputPolicyError("output directory must be absolute or start with ~")
            directory = directory.resolve(strict=True)
            if not directory.is_dir():
                raise OutputPolicyError("output directory must already exist and be a directory")
        except (OSError, RuntimeError):
            raise OutputPolicyError("output directory cannot be resolved") from None
    allow = _table(data.get("allow", {}), {"exact"})
    exact = _table(allow.get("exact", {}), set(SUPPORTED_ENTITIES))
    allow_exact = {kind: frozenset(_strings(values)) for kind, values in exact.items()}
    scope = _table(data.get("scope", {}), {"folders", "extensions"})
    folders = _scope_paths(scope.get("folders", []))
    extensions = _strings(scope.get("extensions", []))
    if any(not re.fullmatch(r"\.[A-Za-z0-9]+", value) for value in extensions):
        raise OutputPolicyError("scanning scope extensions must be dot-prefixed file extensions")
    model = None
    if "model" in data:
        entry = _table(data["model"], {"bundle_directory", "timeout_seconds"})
        raw = entry.get("bundle_directory")
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise OutputPolicyError("model requires an explicitly installed bundle directory")
        try:
            bundle = Path(raw).expanduser()
            if not bundle.is_absolute():
                raise OutputPolicyError("model bundle directory must be absolute or start with ~")
            bundle = bundle.resolve(strict=True)
            if not bundle.is_dir():
                raise OutputPolicyError("model bundle directory must already exist")
        except (OSError, RuntimeError):
            raise OutputPolicyError(
                "model bundle directory cannot be resolved; run explicit model setup"
            ) from None
        timeout = entry.get("timeout_seconds", 30)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 300
        ):
            raise OutputPolicyError("model timeout must be greater than 0 and at most 300 seconds")
        model = ModelPolicy(bundle, float(timeout))
    scopes = _pseudonym_scopes(data.get("pseudonymization", {}))
    activity = _table(data.get("activity", {}), {"enabled", "path"})
    enabled = activity.get("enabled", False)
    if type(enabled) is not bool:
        raise OutputPolicyError("activity enabled must be true or false")
    log_path = None
    if "path" in activity:
        raw = activity["path"]
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise OutputPolicyError("activity path must be a nonempty absolute file path")
        try:
            log_path = Path(raw).expanduser()
        except RuntimeError:
            raise OutputPolicyError("activity path cannot be expanded") from None
        if not log_path.is_absolute() or ".." in log_path.parts or not log_path.name:
            raise OutputPolicyError("activity path must be absolute without parent traversal")
    if enabled and log_path is None:
        raise OutputPolicyError("enabled activity logging requires an explicit path")
    workflow = _table(
        data.get("workflow", {}), {"on_findings", "transform_strategy", "pseudonym_scope"}
    )
    action = workflow.get("on_findings", "ask")
    strategy = workflow.get("transform_strategy", "redact")
    if action not in ("ask", "transform", "stop"):
        raise OutputPolicyError("workflow action must be ask, transform, or stop")
    if strategy not in ("redact", "mask", "remove", "pseudonymize"):
        raise OutputPolicyError(
            "workflow transformation must be redact, mask, remove, or pseudonymize"
        )
    selected_scope = workflow.get("pseudonym_scope")
    if strategy == "pseudonymize":
        selected_scope = _identifier(selected_scope)
        if selected_scope not in scopes:
            raise OutputPolicyError("workflow pseudonym scope is not configured")
    elif selected_scope is not None:
        raise OutputPolicyError("workflow pseudonym_scope requires pseudonymize strategy")
    return OutputPolicy(
        directory,
        allow_exact,
        folders,
        tuple(value.casefold() for value in extensions),
        action,
        strategy,
        selected_scope,
        scopes,
        model,
        ActivityPolicy(enabled, log_path),
    )
