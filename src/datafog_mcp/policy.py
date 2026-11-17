"""Owner-configured policy snapshots, reloaded and validated for each request."""

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

from .config import SUPPORTED_ENTITIES, Strategy

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
# transform_strategy = "redact"  # redact, mask, or remove
"""

Action = Literal["ask", "transform", "stop"]


class OutputPolicyError(ValueError):
    """An unusable policy; its message never includes policy values."""


class _ExactValues(frozenset[str]):
    """Approved values for one entity type, printed as a count only."""

    def __repr__(self) -> str:
        return f"<{len(self)} exact values>"

    __str__ = __repr__


@dataclass(frozen=True)
class Policy:
    """
    Immutable owner settings, including the fixed copy destination.

    Approved allowlist values are held only so is_allowlisted can match them.
    They are left out of repr() and str(), and the supported ways to consult
    them are is_allowlisted, which answers yes or no, and allowlist_counts.
    """

    directory: Path | None = None
    allow_exact: Mapping[str, frozenset[str]] = field(
        default_factory=lambda: MappingProxyType({}), repr=False
    )
    scope_folders: tuple[Path, ...] = ()
    scope_extensions: tuple[str, ...] = ()
    on_findings: Action = "ask"
    transform_strategy: Strategy = "redact"
    missing_scope_folders: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allow_exact",
            MappingProxyType(
                {kind: _ExactValues(values) for kind, values in self.allow_exact.items()}
            ),
        )

    def is_allowlisted(self, entity_type: str, value: str) -> bool:
        """Match an owner-approved value exactly and only for its entity type."""
        return value in self.allow_exact.get(entity_type, frozenset())

    @property
    def allowlist_counts(self) -> dict[str, int]:
        """How many values are approved per entity type, without the values."""
        return {kind: len(values) for kind, values in self.allow_exact.items()}

    @property
    def available_scope_folders(self) -> tuple[Path, ...]:
        """Available folders from this request's validated snapshot."""
        return tuple(
            folder for folder in self.scope_folders if folder not in self.missing_scope_folders
        )

    @property
    def warnings(self) -> list[str]:
        """Report missing scope without exposing policy values in file responses."""
        if self.missing_scope_folders:
            return ["Configured scanning scope folders are missing; routine scope excludes them."]
        return []

    def in_scope(self, path: Path) -> bool:
        """Test advisory scope; callers must enforce roots separately first."""
        folder_match = not self.scope_folders or any(
            path == folder or folder in path.parents for folder in self.available_scope_folders
        )
        extension_match = (
            not self.scope_extensions or path.suffix.casefold() in self.scope_extensions
        )
        return folder_match and extension_match


# The names this class and its loader had before the public interface was
# named. Existing code and tests use them; new code should use Policy.
OutputPolicy = Policy


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


def _refuse_vault(resolved: Path, message: str) -> None:
    """
    Reject a policy path that is the application vault or lies inside it.

    The tools report the copy destination and the scope folders, and refuse
    every path inside the vault. A policy naming the vault would let those two
    answers be put together into the vault's location, so it is unusable. The
    comparison is the one the path checks make, after symlink resolution.

    Parameters:
      resolved: An already-resolved policy path.
      message: The refusal to raise; it names neither the path nor the vault.
    """
    # Import here: the path access layer also loads this policy for writes.
    from .paths import PathNotAllowed, _in_vault

    try:
        inside = _in_vault(resolved)
    except PathNotAllowed as exc:
        # An unusable vault setting; its message names the variable only.
        raise OutputPolicyError(str(exc)) from None
    if inside:
        raise OutputPolicyError(message)


def _scope_paths(value: object) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    # Import here: the path access layer also loads this policy for writes.
    from .paths import DENIED_DIR_NAMES, PathNotAllowed, allowed_roots

    try:
        roots = allowed_roots()
    except PathNotAllowed:
        raise OutputPolicyError("allowed roots cannot be used to validate scanning scope") from None
    folders: list[Path] = []
    missing: list[Path] = []
    for raw in _strings(value):
        try:
            folder = Path(raw).expanduser()
            if not folder.is_absolute():
                raise OutputPolicyError("scanning scope folders must be absolute or start with ~")
            try:
                folder = folder.resolve(strict=True)
            except FileNotFoundError:
                # Resolve existing ancestors/symlinks even for a missing leaf;
                # absence must never bypass root or credential checks below.
                folder = folder.resolve(strict=False)
        except (OSError, RuntimeError):
            raise OutputPolicyError("scanning scope folder cannot be resolved") from None
        if any(part.casefold() in DENIED_DIR_NAMES for part in folder.parts):
            raise OutputPolicyError("scanning scope folder is in a refused credential directory")
        _refuse_vault(folder, "scanning scope folder is inside the application vault directory")
        if not any(folder == root or root in folder.parents for root in roots):
            raise OutputPolicyError("scanning scope folder is outside allowed roots")
        try:
            if not stat.S_ISDIR(folder.stat().st_mode):
                raise OutputPolicyError("scanning scope folders must name directories")
        except FileNotFoundError:
            missing.append(folder)
        except OSError:
            raise OutputPolicyError("scanning scope folder cannot be inspected") from None
        folders.append(folder)
    return tuple(folders), tuple(missing)


def load_policy() -> Policy:
    """Load a strict version-1 policy; only an absent file uses the default."""
    if not os.path.lexists(POLICY_FILE):
        return Policy()
    if not POLICY_FILE.is_file():
        raise OutputPolicyError("output policy is not a regular file")
    try:
        with POLICY_FILE.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        raise OutputPolicyError("cannot read output policy as valid UTF-8 TOML") from None
    if set(data) - {"version", "output", "allow", "scope", "workflow"}:
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
        _refuse_vault(directory, "output directory is inside the application vault directory")
    allow = _table(data.get("allow", {}), {"exact"})
    exact = _table(allow.get("exact", {}), set(SUPPORTED_ENTITIES))
    allow_exact = {kind: frozenset(_strings(values)) for kind, values in exact.items()}
    scope = _table(data.get("scope", {}), {"folders", "extensions"})
    folders, missing_folders = _scope_paths(scope.get("folders", []))
    extensions = _strings(scope.get("extensions", []))
    if any(not re.fullmatch(r"\.[A-Za-z0-9]+", value) for value in extensions):
        raise OutputPolicyError("scanning scope extensions must be dot-prefixed file extensions")
    workflow = _table(data.get("workflow", {}), {"on_findings", "transform_strategy"})
    action = workflow.get("on_findings", "ask")
    strategy = workflow.get("transform_strategy", "redact")
    if action not in ("ask", "transform", "stop"):
        raise OutputPolicyError("workflow action must be ask, transform, or stop")
    if strategy not in ("redact", "mask", "remove"):
        raise OutputPolicyError("workflow transformation must be redact, mask, or remove")
    return Policy(
        directory,
        allow_exact,
        folders,
        tuple(value.casefold() for value in extensions),
        action,
        strategy,
        missing_folders,
    )


load_output_policy = load_policy
