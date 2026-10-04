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
# One absolute path per line; ~ is expanded. Blank lines and lines
# starting with # are ignored.
#
# This file starts out allowing your home directory, the same as having
# no file at all. Replace ~ with narrower directories, for example:
#
# ~/Downloads
# ~/Documents
#
# A file that lists no directories refuses every path. Delete the file
# to return to the default.

~
"""

ALLOWED_ROOTS_VAR = "DATAFOG_MCP_ALLOWED_ROOTS"

# Refused even inside an allowed root
DENIED_DIR_NAMES: frozenset[str] = frozenset({".aws", ".gnupg", ".kube", ".ssh", "gcloud"})


class PathNotAllowed(Exception):
    """
    The path lies outside the roots this server may touch.
    """


class PolicyError(PathNotAllowed):
    """
    The roots configuration exists but cannot be used.

    A broken policy permits nothing, so this subclasses PathNotAllowed: every
    request fails with the reason rather than the server guessing what was
    meant.
    """


@dataclass(frozen=True)
class RootPolicy:
    """
    The roots in force and where they were configured.
    """

    roots: tuple[Path, ...]
    source: str


def _parse(entries: Iterable[str], source: str) -> tuple[Path, ...]:
    """
    Turn raw entries into resolved roots.

    Only whole-line comments are honored, so a path containing a hash is not
    truncated. A relative entry is refused rather than resolved: the working
    directory is wherever the MCP client launched the server, so it could name
    any directory at all.

    Parameters:
      entries: Candidate path strings.
      source: Where the entries came from, for error messages.
    Returns:
      The resolved roots, skipping blanks and comments.
    """
    roots: list[Path] = []
    for entry in (raw.strip() for raw in entries):
        if not entry or entry.startswith("#"):
            continue
        expanded = Path(entry).expanduser()
        if not expanded.is_absolute():
            raise PolicyError(f"{source}: {entry!r} is not an absolute path")
        roots.append(expanded.resolve())
    return tuple(roots)


def _roots_from_env() -> tuple[Path, ...] | None:
    """
    Read roots from the environment.

    Returns:
      The configured roots, or None when the variable is unset. Set but naming
      no directory is a deliberate empty policy, not an absent one.
    """
    raw = os.environ.get(ALLOWED_ROOTS_VAR)
    if raw is None:
        return None
    return _parse(raw.split(os.pathsep), f"${ALLOWED_ROOTS_VAR}")


def _roots_from_file(path: Path) -> tuple[Path, ...] | None:
    """
    Read roots from the config file.

    Anything at the path counts as configuration, including a directory or a
    dangling symlink, so a broken file fails closed instead of reading as
    absent.

    Parameters:
      path: The roots file.
    Returns:
      The configured roots, or None when nothing exists at the path. A file
      listing no roots is a deliberate empty policy.
    """
    if not os.path.lexists(path):
        return None
    if not path.is_file():
        raise PolicyError(f"{path} is not a regular file")
    try:
        body = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise PolicyError(f"{path} is not valid UTF-8") from None
    return _parse(body.splitlines(), str(path))


def policy() -> RootPolicy:
    """
    Resolve the roots in force and where they came from.

    Precedence is the environment variable, then the config file, then the
    user's home directory. The variable wins so a locked-down install cannot be
    widened by editing a file.

    A source that is present takes effect even when it lists no roots, which
    refuses every path. Falling through to the home directory instead would
    mean clearing a policy widens it.

    Returns:
      The roots and a description of their source.
    """
    from_env = _roots_from_env()
    if from_env is not None:
        return RootPolicy(from_env, f"${ALLOWED_ROOTS_VAR}")

    from_file = _roots_from_file(ROOTS_FILE)
    if from_file is not None:
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


def _check(resolved: Path) -> Path:
    """
    Apply the root policy to an already-resolved path.

    The policy is resolved once, so the check and the refusal message cannot
    disagree about which roots were in force.

    Parameters:
      resolved: An already-resolved absolute path.
    Returns:
      The same path, when policy permits it.
    """
    if _is_denied(resolved):
        raise PathNotAllowed(f"{resolved} is in a credential directory")

    current = policy()
    if not current.roots:
        raise PathNotAllowed(
            f"{resolved} is refused because {current.source} lists no allowed roots"
        )
    if not any(resolved == root or root in resolved.parents for root in current.roots):
        roots = ", ".join(str(root) for root in current.roots)
        raise PathNotAllowed(f"{resolved} is outside the allowed roots: {roots}")
    return resolved


def _same_directory(left: Path, right: Path) -> bool:
    """
    Report whether two paths name the same directory.

    Uses .samefile to compare by device and inode instead of just spelling.
    Therefore, a symlink and its target, or two case variants on a case-
    insensitive filesystem, count as the same directory.

    Parameters:
      left: A directory path.
      right: A directory path.
    Returns:
      True when both exist and are the same directory. Otherwise False.
    """
    try:
        return left.samefile(right)
    except OSError:
        return False


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

    Outputs may use an existing directory inside allowed roots. The
    configuration directory and its descendants are refused outright.

    Parameters:
        path: The requested path.
        beside: The resolved input path whose directory bounds the output.
    Returns:
        The resolved path, when policy permits it.
    """
    raw_path = Path(path).expanduser()
    destination = raw_path.parent.resolve() / raw_path.name
    resolved = _check(destination)

    if (
        _same_directory(resolved.parent, ROOTS_FILE.parent)
        or ROOTS_FILE.parent.resolve() in resolved.parents
    ):
        raise PathNotAllowed(f"{resolved} is inside the server's configuration directory")
    if not resolved.parent.is_dir():
        raise PathNotAllowed("output directory must already exist")

    return resolved
