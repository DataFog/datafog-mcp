"""
Where the server is allowed to read and write.
"""

from __future__ import annotations

import os
from pathlib import Path

ALLOWED_ROOTS_VAR = "DATAFOG_MCP_ALLOWED_ROOTS"

# Refused even inside an allowed root
DENIED_DIR_NAMES: frozenset[str] = frozenset({".aws", ".gnupg", ".kube", ".ssh", "gcloud"})


class PathNotAllowed(Exception):
    """
    The path lies outside the roots this server may touch.
    """


def allowed_roots() -> tuple[Path, ...]:
    """
    Resolve the roots this server may read from and write to.

    Reads DATAFOG_MCP_ALLOWED_ROOTS, colon-separated on Linux and macOS, semi-
    colon separated on Windows. Unset falls back to the user's home directory,
    which covers the intended use without exposing system paths or other users'
    files.

    Returns:
      The configured roots, resolved.
    """
    raw = os.environ.get(ALLOWED_ROOTS_VAR, "")
    roots = tuple(
        Path(part).expanduser().resolve() for part in raw.split(os.pathsep) if part.strip()
    )
    return roots or (Path.home().resolve(),)


def _is_denied(resolved: Path) -> bool:
    """
    Report whether a path crosses a credential directory.

    Parameters:
      resolved: An already-resolved absolute path.
    Returns:
      True if any component names a denied directory.
    """
    return any(part in DENIED_DIR_NAMES for part in resolved.parts)


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


def resolve_output(path: str) -> Path:
    """
    Resolve a path the server may write.

    Parameters:
        path: The requested path.
    Returns:
        The resolved path, when policy permits it.
    """
    return _check(Path(path).expanduser().resolve())
