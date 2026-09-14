"""
Where the server is allowed to read and write.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOTS_FILE = Path.home() / ".config" / "datafog" / "allowed_roots"

ROOTS_TEMPLATE = """\
# Directories datafog may read from and write to.
# One path per line. Blank lines and lines starting with # are ignored.
# ~ is expanded.
#
# Uncomment or add the directories you want datafog to reach.

# ~/Downloads
# ~/Documents
"""

ALLOWED_ROOTS_VAR = "DATAFOG_MCP_ALLOWED_ROOTS"

# Refused even inside an allowed root
DENIED_DIR_NAMES: frozenset[str] = frozenset({".aws", ".gnupg", ".kube", ".ssh", "gcloud"})


class PathNotAllowed(Exception):
    """
    The path lies outside the roots this server may touch.
    """


@dataclass(frozen=True)
class RootPolicy:
    """
    The roots in force and where they were configured.
    """

    roots: tuple[Path, ...]
    source: str


def _parse(entries: Iterable[str]) -> tuple[Path, ...]:
    """
    Turn raw entries into resolved roots.

    Only whole-line comments are honored, so a path containing a hash is not
    truncated.

    Parameters:
      entries: Candidate path strings.
    Returns:
      The resolved roots, skipping blanks and comments.
    """
    return tuple(
        Path(entry.strip()).expanduser().resolve()
        for entry in entries
        if entry.strip() and not entry.strip().startswith("#")
    )


def _roots_from_env() -> tuple[Path, ...]:
    """
    Read roots from the environment.

    Returns:
        The configured roots, empty when the variable is unset.
    """
    raw = os.environ.get(ALLOWED_ROOTS_VAR, "")
    return _parse(raw.split(os.pathsep)) if raw.strip() else ()


def _roots_from_file(path: Path) -> tuple[Path, ...]:
    """
    Read roots from the config file.

    Parameters:
      path: The roots file.
    Returns:
      The configured roots, empty when the file is absent or only has comments.
    """
    if not path.is_file():
        return ()
    return _parse(path.read_text(encoding="utf-8").splitlines())


def policy() -> RootPolicy:
    """
    Resolve the roots in force and where they came from.

    Precedence is the environment variable, then the config file, then the
    user's home directory. The variable wins so a locked-down install cannot be
    widened by editing a file.

    Returns:
      The roots and a description of their source.
    """
    from_env = _roots_from_env()
    if from_env:
        return RootPolicy(from_env, f"${ALLOWED_ROOTS_VAR}")

    from_file = _roots_from_file(ROOTS_FILE)
    if from_file:
        return RootPolicy(from_file, str(ROOTS_FILE))

    return RootPolicy((Path.home().resolve(),), "default (home directory)")


def allowed_roots() -> tuple[Path, ...]:
    """
    Resolve the roots this server may read from and write to.

    Returns:
      The roots in force.
    """
    return policy().roots


def _is_denied(resolved: Path) -> bool:
    """
    Report whether a path crosses a credential directory.

    Components are casefolded before comparison to account for case-sensitive
    filesystems.

    Parameters:
      resolved: An already-resolved absolute path.
    Returns:
      True if any component names a denied directory.
    """
    return any(part.casefold() in DENIED_DIR_NAMES for part in resolved.parts)


def _within_allowed(resolved: Path) -> bool:
    """
    Report whether a path sits under a configured root.

    Parameters:
        resolved: An already-resolved absolute path.
    Returns:
        True if the path is inside one of the roots.
    """
    return any(resolved == root or root in resolved.parents for root in allowed_roots())


def _check(resolved: Path) -> Path:
    """
    Apply the root policy to an already-resolved path.

    Parameters:
      resolved: An already-resolved absolute path.
    Returns:
      The same path, when policy permits it.
    """
    if _is_denied(resolved):
        raise PathNotAllowed(f"{resolved} is in a credential directory")
    if not _within_allowed(resolved):
        roots = ", ".join(str(root) for root in allowed_roots())
        raise PathNotAllowed(f"{resolved} is outside the allowed roots: {roots}")
    return resolved


def resolve_input(path: str) -> Path:
    """
    Resolve a path the server may read.

    Symlinks are followed before the policy check, so a link inside an allowed
    root pointing outside it is refused.

    Parameters:
      path: The requested path.
    Returns:
      The resolved path, when policy permits it.
    """
    return _check(Path(path).expanduser().resolve())


def resolve_output(path: str, beside: Path) -> Path:
    """
    Resolve a path the server may write.

    Outputs are confined to the directory of the input they derive from. The
    configuration directory is refused outright too.

    Parameters:
        path: The requested path.
        beside: The resolved input path whose directory bounds the output.
    Returns:
        The resolved path, when policy permits it.
    """
    resolved = _check(Path(path).expanduser().resolve())

    if resolved.parent == ROOTS_FILE.parent:
        raise PathNotAllowed(f"{resolved} is inside the server's configuration directory")
    if resolved.parent != beside.parent:
        raise PathNotAllowed(f"{resolved} must be in the same directory as {beside}")
    return resolved
